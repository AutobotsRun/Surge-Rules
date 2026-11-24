# Surge 规则审核、发布与回滚手册

## 安全边界

- **本仓库绝不读取、上传或修改任何完整 Surge 配置或节点凭据。**
- iPhone 15 Pro 是唯一实验机；iPhone Air 与 M3 MacBook Pro 继续独立运行原有配置。
- `upstreams/catalog.json` 仅列出当前使用的外部 URL；默认 `mode=monitor` 且 `redistribution_approved=false`，不镜像和分发第三方规则。
- GitHub Actions 只改动 GitHub 仓库中的候选文件；没有设备密钥、Surge API 权限、SSH 权限或自动部署步骤。
- `main` 不因上游变化自动更新，只有人工审核并合并 PR 才可能改变。

## 数据结构

- `custom/`：自己编写且可独立验证的 Surge 规则；现有微信 CDN 例外维持原样。
- `upstreams/catalog.json`：21 个原始订阅 URL、许可审查、同步模式、将来拟定的镜像路径。
- `upstreams/state.json`：上游内容的 SHA-256、文件字节数和有效行数；由审计任务生成，**尚不存在时代表未建立基线**。
- `upstream/`：可选的上游规则快照；只有明确完成许可审查、人工把 `mode` 设为 `mirror` 且 `redistribution_approved=true` 才能产生文件。此时还必须检查并保留版权、许可证与原作者来源。
- `.github/workflows/validate.yml`：PR/主分支离线静态检查。
- `.github/workflows/audit-upstreams.yml`：每日北京时间 11:17（UTC 03:17）或在 `main` 手动执行；抓取、校验，然后创建**草稿 PR**，不合并。手动触发其他分支会被 job 条件拒绝。

## 首次启用及日常审核

1. 审核并合并初始化机制的 PR；在主分支上线之前，计划任务不会执行。
2. 在 GitHub `Settings > Actions > General` 核查是否允许 Actions 使用 `GITHUB_TOKEN` 创建 Pull Request。若仓库禁止，该流程会报错而不是绕过限制。
3. 可在 GitHub Actions 手动运行一次 `Audit upstream Surge rules` 以建立首次 SHA-256 基线。首次运行创建含 21 个来源指纹的草稿 PR，但不把监测模式的规则内容下载到仓库。审计工作流会在联网前、创建 PR 前分别运行完整离线单元测试和状态校验；这是必要的，因为由 `GITHUB_TOKEN` 创建的 PR 不应被假定会自动触发 `pull_request` 工作流。
4. 打开 PR 的 Files changed，查看新增/改变的 SHA-256、有效规则数、文件大小。监测模式只提供指纹变化；**想审查具体变化，应打开原作者的源文件/提交 diff**。
5. 内容异常、大量删除、规则类型不兼容、来源或许可无法确认时，不要合并。审查通过后，手工将草稿设为 Ready for review，再人工合并。
6. 审计工作流发现已有 `automation/upstream-audit-` 草稿 PR 时不会覆盖它；必须先处理旧 PR 才会生成下一份。

## 启用镜像的额外条件

1. 人工确认具体文件的原创作者、仓库许可证以及对再分发的适用范围；`logicrw/RuleGo` 目前记为 `UNVERIFIED`。
2. 按上游许可证要求在仓库保留原许可证文本、署名和来源说明，再在新的审核 PR 中把**单个来源**的 `mode` 改为 `mirror`、`redistribution_approved` 改为 `true`；不要一次批量切换。
3. 通过校验、差异审查、iPhone 15 Pro 测试后，再决定是否发布该快照。仓库里即使有快照，也不代表任何设备已启用。
4. 不直接把未经审核的新文件指向稳定设备；默认仅保留上游原 URL。

## 版本固定与回滚

- 测试前先备份 Surge 现有配置，并确认外部规则的引用位置与策略组。
- **正式订阅使用 `stable` 分支**；候选版本使用固定 SHA 验收，确认后才手工推进 `stable` 并记录新旧提交。`main` 不直接用于正式订阅。旧 `Privacy-Curated.list` / `Hijacking-Curated.list` 暂留为兼容路径，不应重复订阅。
- 例如：`https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/<FULL_COMMIT_SHA>/custom/WeChat-CDN.list`；仅示例，未授权设备变更之前不要填进 Surge。
- 如果规则异常：先在实验机恢复原订阅 URL 或此前固定 SHA，并验证规则命中及推送，再恢复其他设备。
- 如果仓库变更错误：在 GitHub 上通过新 PR `git revert <bad_commit_sha>` 回滚并审查。**不要 force push main，不删除历史。**
- 任何状态变更都必须有 PR、对应 commit SHA 和可定位的旧版本；不要求或假定设备会自动回滚。

## 注意事项

- 独立的监测任务不会比较两份上游文件逐行 diff；当 `mode=monitor` 时，只有指纹变更提示和原作者 URL。不能把指纹差异冒充内容审查。
- 审计失败（下载失败、非法编码、HTML、内容过大、规则骤减）时不会提交部分更新。
- 在已有状态文件后新增来源时，审计会为新来源建立基线；移除来源、关闭已有镜像或更改镜像路径需要单独审查并显式清理状态/文件，不会静默丢弃或覆盖。
- 首次合并后需要实测 GitHub Actions 运行结果、PR 创建权限及上游可达性，才能认定自动化已真正投产。
- 本机制对运行中的 Surge 实例执行**零写操作**；一切设备变更要另行得到明确授权。
