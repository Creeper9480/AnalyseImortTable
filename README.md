# Analyse_ImortTable

#### 介绍
> 注意Hello25.exe可能为**恶意程序**，仅作为分析导入表程序使用，请勿直接在本地运行。

此程序用于在PE文件中寻找导入表并分析导入表
Analyse ImortTable in PE file

#### 程序架构
GetPEInfo.py --- 主程序

PEInfo.py --- 分析PE头

ImportTableInfo.py --- 分析导入表

data.py --- 存储了PE文件的结构信息

#### 安装教程

1.  将本项目克隆到本地
2.  在cmd或powershell中运行命令
```bash
 python GetPEInfo.py [filename]
```
- 注意，可选参数`filename`如需使用，请传入绝对路径，若不使用默认分析`hello25 - 20192426.exe`。
