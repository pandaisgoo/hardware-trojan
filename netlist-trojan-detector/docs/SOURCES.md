# 來源與整理紀錄

## 原始實作

- 作者提交來源：`112021101 (1).zip` 的 `112021101 (1)/112021101/`。
- `detector.cpp`、`build.sh`、`run.sh` 逐位元組保留，不替換成 `HW3.zip` 中的較短範例。
- 原始說明來源：使用者提供的硬體木馬偵測 PDF。對外摘要以本版程式與可核對結果為準；差異見 ARCHITECTURE.md。

## 測試資源

- `HW3.zip` 的 `HW3/HW3/README.md`、`public_cases/`、`evaluation/score.py`。
- 原 README 標示 IIS5008 Hardware Security，instructors 為 Yu-Guang Chen、TingTing Hwang；README 自述題目取自 2025 ICCAD CAD Contest Problem A。本次只記錄檔案內的來源敘述，沒有另外核對上游版本或授權。
- 原測試網表、答案與 trojan_definition 未包含在這份整理包；請在確認再散布權利前只保留於本機。

## 整理時新增

README、架構與驗證說明、Python 評估工具、執行結果及內容雜湊。評估器與原 score.py 做了數值交叉核對，但不是聲稱完整執行原 eval.sh。

整理及分析使用 AI 輔助。沒有改寫原演算法、調整門檻或增加新偵測能力；不把本次文件處理描述成原始獨立開發成果。

本包沒有替未確認來源的程式或資料添加統一 LICENSE。原始內容中的註解與來源資訊仍保留；公開前需確認相應規範。
