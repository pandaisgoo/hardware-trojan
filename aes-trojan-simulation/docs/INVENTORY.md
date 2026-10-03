# 檔案盤點與靜態對照

來源：`112021101.zip` 的 `112021101/112021101/`。

三個子目錄 AES、sample_HT、bonus，各自有 5 個 .v；總共 15 個 RTL 檔案。沒有 testbench、Makefile、模擬腳本、參數化測試案例、VCD 或 FSDB。

## 本次能確認的內容

- `AES/AES_top.v` 將 AES 核心輸出經時脈暫存器送出。
- `sample_HT/AES_top.v` 有週期計數器、輸入比對與切換輸出的控制邏輯。
- `bonus/AES_top.v` 有 `match_count`、`prev_pt`、`first_cycle`、`leak_cnt`、`leaking` 等狀態紀錄。
- bonus 的正常 `out` 是 `always @(*)` 指派；AES 與 sample_HT 的 `out` 是時脈觸發的暫存器。做延遲或等價比較時，不能直接假定三者的介面時序相同。

上述是原始碼的靜態觀察，不是重新模擬所得。沒有修改觸發條件、輸出機制或現有 RTL。

## 缺少的重現材料

原 PDF 使用 `make sim file=AES_top_tb.v` 及 `make view file=AES_top_tb.fsdb`，但本次上傳來源裡沒有這些檔案或 Makefile。需要補回原開發目錄的對應版本；不能用推測的 testbench 冒充當時執行版本。

原 PDF 的完成狀態表與波形截圖是既有紀錄，不等於這份精簡提交包可以獨立重現。
