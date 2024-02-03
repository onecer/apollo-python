## 安装
-----

```bash
pip install apollo-python
```

## 使用
-----

导入包
```
from apollo_python import ApolloClient
```

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

## 客户端初始化参数

| 参数               | 说明            | 默认值                   | 环境变量                       |
|:-----------------|:--------------|:----------------------|:---------------------------|
| app_id           | 应用名           | 无                     | APP_ID                     |
| config_url       | 配置中心地址        | http://127.0.0.1:8080 | ${ENV}_META or APOLLO_META |
| cluster          | 集群名           | default               | IDC                        |
| secret           | 访问密钥          | 无                     | APOLLO_ACCESS_KEY_SECRET   |
| env              | 环境            | DEV                   | ENV                        |
| client_ip        | 客户端ip         | 获取当前 IP               | CLIENT_IP                  |
| cache_path       | 配置缓存路径        | tmp/apollo/cache      | APOLLO_CACHE_PATH          |
| need_hot_update  | 是否需要热更新       | True                  | -                          |
| change_listener  | 配置变更监听器(回调函数) | None                  | -                          |
| log_level        | 日志级别          | INFO                  | LOG_LEVEL                  |
| notification_map | 通知配置 (dict)   | None                  | -                          |

### 配置变更监听器 change_listener

```python
"""
接受 4 个参数 
action：delete \ add  \ update
namespace：namespace
key：key
old_value：old_value
"""
def change_listener(action, namespace, key, old_value):
    print(f"action:{action} namespace: {namespace} key: {key} old_value: {old_value}")
```

### 通知配置 notification_map

```python
notification_map = {
    "application": ["application"],
    "application.yml": ["application.yml"]
}
```

## 配置优先级

*** 环境变量 > 代码配置 ***

如果环境变量存在，则优先使用环境变量的值。

如果环境中存在 ENV的环境变量, 如 ENV=DEV。则优先组合出  `DEV_META` 这个环境变量名称来获取 config url。 如果该环境变量不存在，则取 `APOLLO_META` 环境变量的值。如果 `APOLLO_META` 也不存在，则使用代码定义的 config_url 的值。

其它环境变量同理，以此类推。

### 热更新

默认会启动一个线程来定时更新本地缓存的配置，所以，如果每次用的是 get_value 来获取配置，可以实现配置热更新。


## 本地打包 wheel 

```
python3 -m pip install --user --upgrade setuptools wheel
python3 setup.py sdist bdist_wheel  

# upload
twine upload dist/*

```

## License
-------

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any means.

  [My Blog]: [https://uublog.com](https://uublog.com)
