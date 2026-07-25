# File Text Store

基于 Cloudflare Workers + KV 的文件存储与云函数平台，支持文件无损上传下载、在线编辑、JS 沙箱执行。

## 功能

- 文件上传/下载（Base64 无损编码，支持多级目录）
- 大文件分片上传/下载（>5MB 自动分片，>25MB 分片存储，最大 1GB）
- 文本文件在线编辑，图片预览
- 密码保护下载（SHA-256）
- 用户注册/登录，按用户隔离存储
- JS 云函数沙箱（QuickJS WASM），支持参数传入
- API Key 管理（最多 3 个），细粒度权限控制
- 管理员面板（首次安装，可审查所有用户文件和脚本）
- 独立上传页面（`/upload`，通过 API Key 访问）

## 技术栈

- Cloudflare Workers
- Cloudflare KV
- QuickJS (WASM) — JS 沙箱
- Emscripten — WASM 编译

## 部署

### 前置条件

1. 安装 [Node.js](https://nodejs.org/)
2. 安装 [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)：`npm install -g wrangler`
3. 登录 Cloudflare：`wrangler login`

### 创建 KV 命名空间

```bash
wrangler kv:namespace create FILE_STORE
```

将返回的 `id` 填入 `wrangler.toml` 的 `kv_namespaces` 配置中。

### 编译 QuickJS WASM（可选）

如需重新编译 QuickJS WASM 模块，需要 [Emscripten](https://emscripten.org/)：

```bash
cd quickjs/wasm
build.bat
```

编译产物会自动复制到 `src/` 目录。

### 部署

```bash
npm install
npx wrangler deploy
```

## 项目结构

```
├── src/
│   ├── index.js         # Worker 入口（API + 前端 UI）
│   ├── qjs_wasm.js      # QuickJS WASM 模块（编译产物）
│   └── qjs_wasm.wasm    # QuickJS WASM 二进制
├── quickjs/              # QuickJS 源码 + WASM 编译工具（不部署）
│   ├── wasm/
│   │   ├── qjs_wasm.c   # C 包装器
│   │   ├── build.bat    # 编译脚本
│   │   └── emcc_args.txt
│   ├── quickjs.h
│   └── quickjs.c
├── wrangler.toml         # Wrangler 配置
└── package.json
```

## API 接口

### 认证

通过 Session Cookie（Web 登录）或 Bearer Token（API Key）认证：

```
Authorization: Bearer <API_Key>
```

### 文件

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/files?dir=path` | 列出目录 |
| POST | `/api/upload` | 上传文件（multipart） |
| GET | `/api/files/:key/download` | 下载文件 |
| GET | `/api/files/:key` | 获取文件内容 |
| PUT | `/api/files/:key` | 更新文本文件 |
| DELETE | `/api/files/:key` | 删除文件 |
| POST | `/api/mkdir` | 创建目录 |

### 云函数

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/run` | 直接执行代码 |
| GET | `/api/scripts` | 获取脚本列表 |
| POST | `/api/scripts` | 创建/更新脚本 |
| POST | `/api/scripts/:id/run` | 执行已保存脚本 |

代码中通过 `params` 变量访问传入参数，`console.log()` 输出会被捕获返回。

### 响应格式

```json
{
  "output": ["console.log 输出"],
  "result": "代码返回值",
  "error": "错误信息（仅出错时）"
}
```

## License

Apache 2.0