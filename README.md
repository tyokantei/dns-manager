# DNS Manager —— 个人阿里云 DNS 管理面板

按 Daniel 的设计稿实现：通用工具，不写死任何域名；后端复用 demo.py 的
`aliDns` 类（已抽成 `dns_core.py` 并修了 3 处原脚本的毛病，见文件头注释），
前端只负责输入和展示。HTTPS 用自签名证书，**不要把端口转发到公网**，
在局域网 / Tailscale 里用即可。

## 功能

- 记录列表：读取所选主域名的全部阿里云 DNS 记录，可过滤
- 新增记录：主域名下拉选择、RR 自由输入（可空 = 根域名）、类型/线路/TTL 自选，
  带实时「解析预览」
- 修改记录：列表里点「修改」，回填表单后保存
- 删除记录：二次确认后直删
- 模板库：内置 5 个示例模板（Jetson设备/家庭NAS/影音服务/远程管理/域名别名），
  也可把当前表单存为自己的模板，一键套用
- 批量新增：多个前缀共用同一类型/记录值，一次提交
- 动态 IP 更新：只把指定前缀的 A 记录改到新 IP（可一键获取当前公网 IP），
  不影响其他记录
- 密钥档案：支持多个阿里云账号（档案），每个档案填 AccessKey 与管辖域名；
  密钥只存在服务器本地 `data/store.json`（权限 600），页面永不回显

## 部署（edge640）

1. 拉取仓库：

   ```bash
   cd ~
   git clone git@github.com:tyokantei/dns-manager.git
   ```

2. 直接运行：

   ```bash
   cd ~/dns-manager
   /opt/python3.10/bin/python3 app.py --port 8550
   ```

   首次启动会自动生成自签名证书（cert.pem / key.pem）。
3. 浏览器打开 `https://<edge640 的局域网 IP>:8550`，证书警告点「继续」，
   先设置面板密码，然后到页面底部「设置」里添加密钥档案
   （建议用只授 DNS 权限的 RAM AccessKey）。
4. 常驻运行（可选）：改 `dns-manager.service` 里的路径与用户，
   `cp dns-manager.service /etc/systemd/system/ && systemctl enable --now dns-manager`。

## 文件

- `app.py` —— Web 服务（标准库，含登录/会话/档案/模板存储）
- `dns_core.py` —— 阿里云 DNS 操作库（源自 demo.py）
- `web/index.html` —— 前端单文件
- `data/` —— 运行时生成：`auth.json`（密码哈希）、`store.json`（档案+模板），均 600
- `cert.pem` / `key.pem` —— 运行时生成的自签名证书
