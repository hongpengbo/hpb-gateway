# hpb-gateway
微服务网关

# gradlew.bat的作用
`gradlew.bat` 是 Gradle Wrapper 的 Windows 批处理脚本文件。

## 主要作用
1. **自动下载和管理 Gradle 版本**
    - 当你运行 `gradlew.bat` 时，它会根据项目中 `gradle/wrapper/gradle-wrapper.properties` 文件定义的版本自动下载对应的 Gradle
    - 确保所有开发者使用相同版本的 Gradle，避免版本兼容性问题
2. **无需手动安装 Gradle**
    - 即使你的系统没有安装 Gradle，也可以通过这个脚本运行构建命令
    - 首次运行时会下载 Gradle 到本地缓存
3. **常用命令**
   ```bash
   gradlew.bat build          # 构建项目
   gradlew.bat clean          # 清理构建文件
   gradlew.bat test           # 运行测试
   gradlew.bat bootRun        # 运行 Spring Boot 应用
   ```
## 与 `gradlew` 的区别
- **`gradlew.bat`** - 用于 Windows 系统
- **`gradlew`** - 用于 Linux/Mac 系统（Shell 脚本）