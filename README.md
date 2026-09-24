# svarog-eddsa-sparkle

本库实现基于 Curve25519 的 Sparkle 门限 EdDSA。
公开接口包含分布式密钥生成 `keygen`、批量签名 `sign_batch` 和份额轮换 `reshare`。
份额轮换保持参与方集合与门限不变；消息传输由调用方实现 `curve_abstract::TrMessenger` 提供。

## 使用

```toml
[dependencies]
svarog-eddsa-sparkle = "0.1.0"
```

接口从 crate 根导出，具体参数和返回值见 API 文档。
曲线、标量及 Shamir 份额操作使用 crates.io 上的 Svarog 代数库。
调用方负责参与方配置、会话编号与通信编排。

## 发布检查

`0.1.0` 从 `main` 分支准备发布，正式版本以最终提交和 `v0.1.0` 标签对应的源码为准。
检查脚本依次执行格式检查、测试、Clippy、文档构建、打包与发布预演，任一步失败都会停止。
依赖使用根目录的 `Cargo.lock`，测试使用四个并行测试线程。

```bash
scripts/prepublish.sh
```

打包与预演需要访问 crates.io，默认要求待打包文件已经提交。
在提交前检查本地修改时，可以显式使用 `--allow-dirty`。
脚本始终保留 `--dry-run`，CI 在 `main` 的推送及合并请求上执行默认检查。

```bash
scripts/prepublish.sh --allow-dirty
```

## 正式发布

将发布准备修改提交到 `main`，在干净工作区重跑默认检查。
核对最终提交并创建 `v0.1.0` 标签后，执行 `cargo publish --locked` 上传。
发布完成后，将对应提交和标签推送到远端，确保源码可追溯。

## 许可证

本库采用 `MIT OR Apache-2.0` 双许可证，使用者可任选其一。
完整文本见 [LICENSE-MIT](LICENSE-MIT) 和 [LICENSE-APACHE](LICENSE-APACHE)。
依赖库继续遵循各自的许可证。
