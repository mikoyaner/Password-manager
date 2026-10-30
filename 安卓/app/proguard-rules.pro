# 保留 Bouncy Castle（反射加载算法实现）
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# 保留本项目加密/数据核心（可能被反射或需保持字段名与 JSON 对应）
-keep class com.pwdmgr.Crypto { *; }
-keep class com.pwdmgr.Vault { *; }
