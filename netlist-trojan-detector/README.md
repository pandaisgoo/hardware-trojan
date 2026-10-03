# 基於網表拓樸分析的硬體木馬偵測器

以 C++17 實作靜態閘級網表分析：讀取 Verilog 網表，建立邏輯閘與訊號線的驅動／讀取關係，再以十組特徵規則篩選硬體木馬候選區域，輸出判定及候選閘名稱。

## 分析流程

```text
Gate-level Verilog
       ↓
Tokenizer / netlist parser
       ↓
gate_map + wire_driver + wire_readers
       ↓
Ten feature-rule searches launched with std::async
       ↓
Fixed-priority selection (0 → 9)
       ↓
NO_TROJAN / TROJANED + candidate gate list
```

規則使用 BFS、DFF 回饋或鏈狀結構、組合邏輯區域大小、邏輯閘類型比例及向區域外連接的訊號等條件。函式名稱中的 `is_isomorphic` 不代表通用精確子圖同構求解器；此版本是特徵式啟發法。

## 本次可重現結果

以下是未修改 `detector.cpp`，在所提供的 270 筆 `public_cases` 上重新執行所得。這些案例曾用於開發，並非獨立的隱藏測試集。

| 指標 | 結果 |
|---|---:|
| 網表總數 | 270 |
| 含木馬 / 無木馬案例 | 180 / 90 |
| 有無木馬判斷正確 | 235 / 270（87.04%） |
| TP / TN / FP / FN（以木馬為正類） | 160 / 75 / 15 / 20 |
| 網表級 precision / recall | 91.43% / 88.89% |
| 閘級 F1：對 180 筆正例取平均，漏判以 0 計 | 0.29354 |
| 閘級 F1：僅對 160 筆判對的正例取平均 | 0.33023 |
| 正例中候選閘集合完全相同 | 2 / 180 |
| 執行失敗 / 逾時 | 0 / 0 |

**分類正確不等於閘級定位正確。**此版本較能判斷有無木馬，但精確圈出相關閘仍有明顯限制。完整結果包含逐案例 CSV、270 份預測、摘要與雜湊紀錄，見 [驗證說明](docs/VALIDATION.md) 及 `results/public_cases_baseline/`。

## 建置與單筆執行

已測試環境：Linux x86-64、g++ 14.2.0。此處僅記錄本次環境，不宣稱其他平台皆已驗證。

```bash
bash build.sh
bash run.sh /path/to/design.v prediction.txt
```

`build.sh` 使用 `g++ -O3 -std=c++17 -pthread`。預測檔路徑的父資料夾必須事先存在。Windows 使用者需在具備 Bash 與 C++ 編譯器的 Linux 環境執行；不將上述命令視為已驗證的原生 PowerShell 流程。

## 重跑完整測試

從原資料包保留 `public_cases/` 於本機，不必複製到公開倉庫。Python 3.10 以上執行：

```bash
python3 tools/evaluate.py \
  --binary ./detector \
  --source ./detector.cpp \
  --cases /path/to/public_cases \
  --out results/local_run
```

評估程式要求輸出目錄不存在或為空，避免蓋掉保留結果。每筆輸入會被複製成暫存的 `input.v`；參考答案只由評估程式讀取。

## 內容與限制

`detector.cpp`、`build.sh`、`run.sh` 均保留提交檔內容，沒有為提高測試分數改動規則或門檻。`tools/evaluate.py` 與此 README 為整理時新增。

此套件沒有包含基準網表、答案檔、十個 RTL 範本或編譯好的執行檔；不代表測資可無條件再散布。來源見 [SOURCES.md](docs/SOURCES.md)，架構見 [ARCHITECTURE.md](docs/ARCHITECTURE.md)。

現有規則針對既定範本設計；不宣稱能偵測任意未知木馬、完全解析任意 Verilog，或證明任何網表安全。此偵測器也尚未與另一個 AES RTL 實作完成端到端驗證。
