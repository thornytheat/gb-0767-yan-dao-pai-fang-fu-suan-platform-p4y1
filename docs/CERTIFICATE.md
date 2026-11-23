# 复核监测证据单

从留档打开签发页，确认运行编号、监测烟道和分钟差额后下载一份 JSON。`originals` 中的原件解码成文本后以 UTF-8 重新编码，逐文件计算 SHA-256，应等于 `manifest.sha256`。

核验 `sha256` 时，从附件取出 `manifest`、`originals` 和 `results` 组成对象。深度排序对象键，以 UTF-8 编码 JSON，保留中文原字符，分隔符使用逗号和冒号且省略空白。结果是内容校验摘要。原件可用 `files` 对象重新归档，以 `run_id` 和逐行判据对照两次计算。

按 `results.validity.rows[].sources` 找分钟原件，`mode_sources` 定位工况；按 `results.reports.rows[].reports` 找报送单据。错误版本及 CSV 结构错误分别见 `oxygen.isolated` 和 `intake.files[].rejected`。

## 授权小时证据单（对外）

外部复核员一次只获准查一个整点小时，整份原件超出授权范围。在签发页选择授权小时后 `POST /api/authorizations/{run_id}`（请求体 `{"hour": "<带偏移的 UTC 整点>"}`），再以返回的 `authorization_id` 通过 `GET /api/authorizations/{run_id}/{auth_id}` 下载 JSON。

- 证据单只含该小时 60 个分钟槽位的裁决（`verdicts.minutes`）、小时汇总（`verdicts.hour`）与该小时对账行（`verdicts.report`），以及 `sources` 中被这些裁决引用到的分钟、工况、报送原件行；不含任何其他小时的数据，也不含 `originals` 完整原件文本。完整原件仍只在内部留档与 `GET /api/export/{id}` 可取。
- 横跨整点的工况记录**整条保留**（`sources.modes` 保留原始 start/end，不在小时边界截断），否则边界免计分钟会被误判为缺证；区间非法的工况不具免计效力，只出现在 `verdicts.isolated_modes`。
- 同一次授权（同一 `run_id` + 同一 UTC 小时，时区写法不同也视为同一小时）重试不新增证据单：台账以 `(run_id, scope.hour)` 唯一约束保证只存一行，重复请求返回 `reused=true` 与同一 `authorization_id`，并发重试同样只落一行。
- 复核员可独立复算：用 `scope.window` 重建窗口，对 `sources.minutes` 依次跑修订采信、折算、有效性裁决，对 `sources.modes` 跑工况免计，再以 60 条裁决做小时平均，应逐行等于 `verdicts` 且小时浓度等于 `verdicts.hour.mg_nm3`；用 `sources.reports` 复算报送差额。
- 校验 `sha256`：取去掉 `sha256` 键后的整个对象，按上述同一规范（深排序、UTF-8、保留中文、紧凑分隔）摘要。`verify_authorization` 还会核对 60 条裁决的有效/免计/缺证计数与小时汇总一致（分钟勾稽）。`checks.source_sha256` 是各类裁剪后原件行的独立摘要。

