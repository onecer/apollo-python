## 安装
-----

```bash
pip install apollo-client
```

## 使用
-----


```
app_id = 'demo-service'
config_url = 'http://127.0.0.1:8080'
cluster = 'default'
secret = ''
env = 'DEV'

client = ApolloClient(app_id=app_id, config_url=config_url, cluster=cluster, secret=secret, env=env)
lm_API_KEY = client.get_value("lm_API_KEY")
```

也默认支持通过环境变量来传递值,基本和 Java 客户端保持一致
|环境变量|对应的字段|
|:---|:---|
|APP_ID|app id 应用名|
|IDC| cluster 集群名|
｜ENV｜ 环境 默认（DEV）｜
|APOLLO_ACCESS_KEY_SECRET|访问密钥|
|CLIENT_IP| 默认会自己获取，但是也可以支持自己传递 |
|APOLLO_CACHE_PATH|配置缓存路径|
|APOLLO_META| config url|

如果环境中存在 ENV的环境变量, 如 ENV=DEV。则优先组合出  `DEV_META` 这个环境变量名称来获取 config url。 如果该环境变量不存在，则取 `APOLLO_META` 环境变量的值。如果 `APOLLO_META` 也不存在，则使用代码定义的 config_url 的值。

其它环境变量同理，以此类推。

### 热更新

默认会启动一个线程来定时更新本地缓存的配置，所以，如果每次用的是 get_value 来获取配置，可以实现配置热更新。


## License
-------

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any means.

  [My Blog]: [https://uublog.com](https://uublog.com)
