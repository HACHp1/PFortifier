# PFortifier

This is the code for the paper: PFORTIFIER: Mitigating PHP Object Injection through Automatic Patch Generation.  
Our work will appear at IEEE S&P 2025.  
Please cite the above paper if you use our code.  
The code is released under the GPLv3.

## Introduction

* PHP pop链自动化挖掘
* patch自动生成
* neo4j图查询辅助挖掘
* 修复了部分phply无法解析新语法的问题
* ~~payload自动生成（已废弃）~~

## 安装

* 安装python
* 安装py2neo：`pip install py2neo`
* （可选）安装neo4j，密码设置为password

## Reproducing the results in the paper

* 从 [<https://github.com/CyanM0un/PFortifier_DataSet>] 下载PHP代码数据集，保留config.py中的默认配置，设置待扫描的代码路径（php_prog_root），运行Main.py。
* 完成扫描和patch生成后，结果储存在result路径下：
* * pop_chains.json：扫描到的POP链
* * patch.json：POP链对应的patch
* * patch_collect.json：去重后的patch，方便开发人员人工审计、修复
* * unable2patch_entry.json：生成suggestion而不是直接patch的入口

## 使用 in real world

* 设置好config.py中的各项，运行Main.py

### 超参数说明

* php_prog_root: 要扫描的PHP项目的根目录
* gc_switch：是否开启垃圾收集，开启后可以节省内存使用，但会降低扫描速度
* patch_generate：是否生成修复补丁
* graph_gen：是否开启neo4j图数据库收集
* use_pm_summary：是否开启summary加速模式，建议开启，原理详见论文
* skip_overdetected：是否跳过过多的链子，POP链挖掘会产生很多nodes，PM模式下，不会过滤部分入口和sink相同的链子，因此，此选项开启后可以在PM模式过滤一部分入口相同的链节，使结果的数量与非PM模式相吻合
* filter_sink：对同一entry是否只记录一个sink一次（entry-sink pair）
* use_cache：是否开启缓存，**再次**扫描同一套代码时可以使用
* exclude_die_wakeup：排除在wakeup函数中有 "die()"的入口
* entry_func_li：POP链的入口方法, 比如__destruct
* max_pm_length：限制查找的PM链长度（仅PM）
* max_normal_length: 限制查找的链长度（所有方法、函数）；tips: max_pm_length和max_normal_length可以根据情况选择一个设置为999999，只限制另一个
* each_entry_early_stop_num：每个入口记录的链最大数，防止记录的链过多
* entry_depth：入口深度，即将多少长度的起始链节作为入口
* early_stop_num：总最大链数，超过时将不会记录，防止记录的链过多

### 超参数最佳实践

对于不同目的采用的不同超参数。超参数列表：

* max_pm_length：推荐小于6，PM的最大长度，太长了扫不完，太短了扫不全
* max_normal_length：设置9扫起来比较快，特别是大框架，对于一些特殊的情况可以增大
* entry_depth：默认1，一些特殊情况可以2，3；入口深度越大，入口发掘能力越强，对于patch模式可以设置高一点
* 调用图会收集所有的sink链，不会因为以上超参数略过链子
* pop链信息和patch信息受以上超参数影响
* pop链挖掘模式下（主要是挖新链子）：each_entry_early_stop_num建议999999；entry_depth可以视扫描的总代码数量情况定1-3，甚至更深一点；early_stop_num可以设置大一些，比如3000
* patch模式下（主要是对应用进行pop修复）：each_entry_early_stop_num可以设置小一点，比如5；entry_depth可以定大一点，比如3；early_stop_num为1000，或者适当调整；对于大框架patch时，可以关闭PM summary，并且each_entry_early_stop_num设置小一点

### 其他使用技巧

* 可以注释掉不关心的php代码，灵活使用注释
* 使用neo4j查询的链子比直接扫出的链子更多，可以自由搭配
* sink数较多并仅想修复chains时，建议关闭pm summary并设置each_entry_early_stop_num = 5

### neo4j

查询长度3-5的反序列化链：

```mysql
MATCH p=(m1:Method{MethodName:"__destruct"})-[*3..5]->(m2{IsSink:TRUE}) RETURN p limit 25
```

## 一些细节

* 虽然PHP本身不区分大小写，但vendor/autoload.php区分大小写，否则无法识别出具体的类，所以PFortifier也区分类和命名空间的大小写

## LICENSE

[LICENSE](/COPYING)
