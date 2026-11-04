import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataType;
import java.io.*;
import java.util.*;


/**
 * IosGhidraDump.java — iOS 敏感 API 调用链提取（Ghidra postScript）
 * ================================================================
 * 对齐 Android 版 extract_sensitive_calls.py 的角色：
 *   敏感 API 调用点（iOS = C 函数/ObjC 方法） → 调用方（caller_chain） → 反编译片段。
 *
 * 敏感 API 清单（iOS 隐私合规口径）：
 *   位置：CLLocationManager 及 delegate 方法、CCLocation 反向地理编码
 *   通讯录：CNContactStore / ABAddressBook
 *   相机/相册：AVCaptureDevice / UIImagePickerController / PHPhotoLibrary
 *   麦克风：AVAudioRecorder / AVAudioSession
 *   设备标识：advertisingIdentifier (ASIdentifierManager) / identifierForVendor / openURL
 *   剪贴板：UIPasteboard
 *   传感器/其他：motionManager / NSFileManager (隐私目录) / WKWebsiteDataStore
 *
 * 输出 JSON（stdout 重定向落盘）：
 *   { total_functions, objc_classes, sensitive_calls: [{api, class, method, address, callers:[...], snippet}...],
 *     strings: [...], objc_class_list: [...] }
 */
public class IosGhidraDump extends GhidraScript {

    static final String[] SENSITIVE_C = {
        "CLLocationManager", "CNContactStore", "ABAddressBook", "AVCaptureDevice",
        "UIImagePickerController", "PHPhotoLibrary", "AVAudioRecorder", "AVAudioSession",
        "ASIdentifierManager", "advertisingIdentifier", "identifierForVendor",
        "UIPasteboard", "CMMotionManager", "NSFileManager", "WKWebsiteDataStore",
        "CTTelephonyNetworkInfo", "UIDevice", "openURL",
        "ADClient", "SKAdNetwork", "NSPersistentContainer", "LAContext",
        "ATTrackingManager", "requestTrackingAuthorization", "CNCopyCurrentNetworkInfo",
        "CTCarrier", "SSKeychain", "SecItemAdd", "SecItemCopyMatching"
    };
    static final String[] SENSITIVE_SEL = {
        "requestWhenInUseAuthorization", "requestAlwaysAuthorization", "startUpdatingLocation",
        "requestAccess", "enumerateAssets", "requestAuthorizationStatus",
        "advertisingIdentifier", "identifierForVendor", "generalPasteboard",
        "stringByAddingPercentEncoding", "valueForKey:", "setValue:forKey:",
        "contentChangeCount", "beginRecording", "hasMicrophonePermission",
        "requestTrackingAuthorization", "copyCurrentNetworkInfo", "carrierName"
    };

    @Override
    public void run() throws Exception {
        PrintStream out = System.out;
        out.println("===IOS_DUMP_BEGIN===");

        // 1) 函数与 ObjC 类清单
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int total = 0;
        Map<String, Integer> classMethodCount = new TreeMap<>();
        List<Function> allFuncs = new ArrayList<>();
        while (it.hasNext()) {
            Function f = it.next();
            total++;
            allFuncs.add(f);
            Namespace ns = f.getParentNamespace();
            String nsName = ns.getName();
            if (!nsName.equals("Global") && !nsName.equals("EXTERNAL") && !nsName.equals("Library")
                    && !nsName.equals("SymbolTable")) {
                classMethodCount.merge(nsName, 1, Integer::sum);
            }
        }
        out.println("TOTAL_FUNCTIONS:" + total);
        out.println("OBJC_CLASSES:" + classMethodCount.size());

        // 2) 敏感 API 调用扫描
        //    思路A：函数体内 call 引用命中敏感符号名
        //    思路B（iOS ObjC 关键路径）：程序内引用的字符串/sel 含敏感方法名
        //            （startUpdatingLocation 等 sel 以字符串常量存在于 __objc_methname，
        //             直接扫 defined data 的字符串 + 其引用者）
        ReferenceManager rm = currentProgram.getReferenceManager();
        Set<String> sensitiveHitNames = new HashSet<>();
        for (String s : SENSITIVE_C) sensitiveHitNames.add(s);
        for (String s : SENSITIVE_SEL) sensitiveHitNames.add(s);

        Map<Function, Set<String>> funcHits = new LinkedHashMap<>();
        // 思路B：字符串常量表扫描（sel 名/类名），再取引用者函数
        DataIterator dit = currentProgram.getListing().getDefinedData(true);
        Map<String, List<Function>> selCallers = new LinkedHashMap<>();
        while (dit.hasNext()) {
            Data d = dit.next();
            Object v = d.getValue();
            if (v instanceof String) {
                String s = (String) v;
                String matched = null;
                for (String key : sensitiveHitNames) {
                    if (s.equals(key) || (key.length() > 8 && s.contains(key))) {
                        matched = key; break;
                    }
                }
                if (matched == null) continue;
                // 找引用这个字符串的函数
                for (Reference r : rm.getReferencesTo(d.getAddress())) {
                    Function cf = currentProgram.getFunctionManager()
                            .getFunctionContaining(r.getFromAddress());
                    if (cf != null) {
                        funcHits.computeIfAbsent(cf, k -> new LinkedHashSet<>()).add(s);
                    }
                }
            }
        }
        out.println("SEL_STRING_HITS:" + funcHits.size());

        // 思路A：函数体内 call 引用
        for (Function f : allFuncs) {
            AddressSetView body = f.getBody();
            AddressIterator ai = rm.getReferenceSourceIterator(body, true);
            Set<String> hits = funcHits.computeIfAbsent(f, k -> new LinkedHashSet<>());
            while (ai.hasNext()) {
                Address a = ai.next();
                for (Reference r : rm.getReferencesFrom(a)) {
                    if (r.getReferenceType().isCall()) {
                        SymbolTable st = currentProgram.getSymbolTable();
                        for (Symbol sym : st.getSymbols(r.getToAddress())) {
                            String n = sym.getName();
                            for (String key : sensitiveHitNames) {
                                if (n.contains(key)) { hits.add(n); }
                            }
                        }
                    }
                }
            }
        }
        // 思路C：ObjC 外部类引用（__objc_classrefs 指向 EXTERNAL 符号 _OBJC_CLASS_$_CLLocationManager 等）
        //        引用这些指针的函数 = 使用该敏感类的函数（数据引用，非 call）
        SymbolTable st2 = currentProgram.getSymbolTable();
        SymbolIterator sit = st2.getExternalSymbols();
        int externalClassHits = 0;
        while (sit.hasNext()) {
            Symbol sym = sit.next();
            String n = sym.getName();
            if (!n.startsWith("_OBJC_CLASS_$_")) continue;
            String cls = n.substring("_OBJC_CLASS_$_".length());
            boolean sensitive = false;
            for (String key : sensitiveHitNames) {
                if (cls.contains(key)) { sensitive = true; break; }
            }
            if (!sensitive) continue;
            externalClassHits++;
            for (Reference r : rm.getReferencesTo(sym.getAddress())) {
                Function cf = currentProgram.getFunctionManager()
                        .getFunctionContaining(r.getFromAddress());
                if (cf != null) {
                    funcHits.computeIfAbsent(cf, k -> new LinkedHashSet<>()).add(cls);
                }
            }
        }
        out.println("EXTERNAL_CLASS_HITS:" + externalClassHits);
        funcHits.values().removeIf(v -> v.isEmpty());
        out.println("SENSITIVE_CALLS:" + funcHits.size());

        // 3) 反编译命中函数 + 上溯一层调用方
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        int emitted = 0;
        for (Map.Entry<Function, Set<String>> e : funcHits.entrySet()) {
            Function f = e.getKey();
            if (emitted >= 400) break;  // 上限防爆炸
            // 调用方
            List<String> callers = new ArrayList<>();
            for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
                if (r.getReferenceType().isCall()) {
                    Function cf = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    if (cf != null) callers.add(cf.getName(true));
                }
            }
            DecompileResults res = decomp.decompileFunction(f, 60, monitor);
            String code = "";
            if (res.decompileCompleted()) {
                code = res.getDecompiledFunction().getC();
                if (code.length() > 2200) code = code.substring(0, 2200) + "\n/* truncated */";
            }
            Namespace ns = f.getParentNamespace();
            String rec = String.format("{\"cls\":\"%s\",\"method\":\"%s\",\"apis\":[%s],\"callers\":[%s],\"snippet\":%s}",
                esc(ns.getName()), esc(f.getName()),
                quoted(e.getValue()),
                quoted(callers),
                jsonStr(code));
            out.println("SENSITIVE:" + rec);
            emitted++;
        }

        // 3.5) 端点引用分析：http(s) URL 常量 → 引用函数（调用链）→ 反编译片段（字段线索）
        //      注意：DataIterator 一次性，重新获取
        Map<String, LinkedHashSet<Function>> urlCallers = new LinkedHashMap<>();
        DataIterator ditEp = currentProgram.getListing().getDefinedData(true);  // 新迭代器
        int dbgUrlFound = 0, dbgUrlWithAnyRef = 0, dbgUrlL1 = 0, dbgUrlL2 = 0;
        while (ditEp.hasNext()) {
            Data d = ditEp.next();
            Object v = d.getValue();
            if (v instanceof String) {
                String s = (String) v;
                if ((s.startsWith("http://") || s.startsWith("https://"))
                        && s.length() > 10 && s.length() < 300) {
                    dbgUrlFound++;
                    LinkedHashSet<Function> fs = new LinkedHashSet<>();
                    java.util.List<Reference> lvl1 = new java.util.ArrayList<>();
                    for (ReferenceIterator ri = rm.getReferencesTo(d.getAddress()); ri.hasNext(); ) {
                        Reference r = ri.next();
                        lvl1.add(r);
                        Function cf = currentProgram.getFunctionManager()
                                .getFunctionContaining(r.getFromAddress());
                        if (cf != null) fs.add(cf);
                    }
                    if (!lvl1.isEmpty()) dbgUrlWithAnyRef++;
                    if (!fs.isEmpty()) dbgUrlL1++;
                    // 二级：iOS 实际链路是 代码函数 --ref--> __cfstring 结构 --ptr--> 字符串
                    // 字符串的 lvl1 引用来自 cfstring 结构（非函数体），需要从 cfstring 地址反查代码
                    if (fs.isEmpty()) {
                        for (Reference r : lvl1) {
                            Address cfAddr = r.getFromAddress();
                            for (ReferenceIterator ri2 = rm.getReferencesTo(cfAddr); ri2.hasNext(); ) {
                                Reference r2 = ri2.next();
                                Function cf = currentProgram.getFunctionManager()
                                        .getFunctionContaining(r2.getFromAddress());
                                if (cf != null) fs.add(cf);
                            }
                        }
                        if (!fs.isEmpty()) dbgUrlL2++;
                    }
                    // 三级：iOS cfstring 结构 = {isa, flags, char* data, length}，
                    //      L1 引用来自 cfstring 结构基地址（UNDEFINED 数据），代码引用的是结构体+16 处的指针字段
                    if (fs.isEmpty()) {
                        for (Reference r : lvl1) {
                            Address cfBase = r.getFromAddress();
                            for (long off : new long[]{16, 8, 24, 0}) {
                                Address field = cfBase.add(off);
                                for (ReferenceIterator ri2 = rm.getReferencesTo(field); ri2.hasNext(); ) {
                                    Reference r2 = ri2.next();
                                    Function cf = currentProgram.getFunctionManager()
                                            .getFunctionContaining(r2.getFromAddress());
                                    if (cf != null) fs.add(cf);
                                }
                                if (!fs.isEmpty()) break;
                            }
                        }
                        if (!fs.isEmpty()) dbgUrlL2++;
                    }
                    if (!fs.isEmpty()) urlCallers.put(s, fs);
                }
            }
        }
        out.println("URL_DEBUG found=" + dbgUrlFound + " withRef=" + dbgUrlWithAnyRef
                + " l1=" + dbgUrlL1 + " l2=" + dbgUrlL2);
        out.println("ENDPOINTS:" + urlCallers.size());
        int eps = 0;
        for (Map.Entry<String, LinkedHashSet<Function>> e : urlCallers.entrySet()) {
            if (eps >= 40) break;
            LinkedHashSet<Function> fs = e.getValue();
            if (fs.isEmpty()) continue;
            String snip = "";
            try {
                DecompileResults res = decomp.decompileFunction(fs.iterator().next(), 45, monitor);
                if (res.decompileCompleted()) {
                    snip = res.getDecompiledFunction().getC();
                    if (snip.length() > 1500) snip = snip.substring(0, 1500) + "\n/* truncated */";
                }
            } catch (Exception ignore) {}
            StringBuilder cnames = new StringBuilder();
            int i = 0;
            for (Function f : fs) {
                if (i++ > 0) cnames.append(",");
                cnames.append(jsonStr(f.getName(true)));
                if (i >= 5) break;
            }
            String rec = String.format("{\"url\":\"%s\",\"callers\":[%s],\"snippet\":%s}",
                esc(e.getKey()), cnames, jsonStr(snip));
            out.println("ENDPOINT:" + rec);
            eps++;
        }

        decomp.dispose();

        // 4) 类清单（供 LLM 一方/三方语义聚类）
        out.println("CLASS_LIST_BEGIN");
        for (Map.Entry<String, Integer> e : classMethodCount.entrySet()) {
            out.println("CLS:" + e.getKey() + "|" + e.getValue());
        }
        out.println("CLASS_LIST_END");

        out.println("===IOS_DUMP_END===");
    }

    static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\""); }
    static String jsonStr(String s) { return "\"" + esc(s).replace("\n", "\\n").replace("\r", "") + "\""; }
    static String quoted(Collection<String> c) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (String s : c) { if (i++ > 0) sb.append(","); sb.append(jsonStr(s)); if (i >= 8) break; }
        return sb.toString();
    }
}
