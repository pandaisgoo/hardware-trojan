// IIS5008 HW3 - Hardware Trojan Detection
// Usage:  ./detector <design.v> <output.txt>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <queue>
#include <utility>
#include <algorithm>
#include <future>

struct Gate {
    std::string type;
    std::string name;
    std::vector<std::string> inputs;  // 專門儲存輸入腳位
    std::vector<std::string> outputs; // 專門儲存輸出腳位
};

struct Graph {
    std::unordered_map<std::string, Gate> gate_map;
    std::unordered_map<std::string, std::string> wire_driver; // 記錄線是從哪個閘出來的
    std::unordered_map<std::string, std::vector<std::string>> wire_readers; // 記錄線進到了哪些閘
};

std::string extract_wire_from_pin(const std::string& pin) {
    size_t start = pin.find('(');
    size_t end = pin.find(')');
    if (start != std::string::npos && end != std::string::npos && end > start) {
        return pin.substr(start + 1, end - start - 1);
    }
    return "";
}

std::string normalize_gate_type(std::string raw_type) {
    std::transform(raw_type.begin(), raw_type.end(), raw_type.begin(), ::tolower);
    if (raw_type.find("dff") != std::string::npos || raw_type.find("fdre") != std::string::npos) return "dff";
    if (raw_type.find("xor") != std::string::npos || raw_type.find("xnor") != std::string::npos) return "xor";
    if (raw_type.find("nand") != std::string::npos) return "nand"; 
    if (raw_type.find("and") != std::string::npos) return "and";
    if (raw_type.find("nor") != std::string::npos) return "nor";   
    if (raw_type.find("or") != std::string::npos) return "or";
    if (raw_type.find("buf") != std::string::npos) return "buf";
    if (raw_type.find("not") != std::string::npos || raw_type.find("inv") != std::string::npos) return "not";
    if (raw_type.find("mux") != std::string::npos) return "mux";
    return raw_type;
}

Graph build_graph(std::vector<Gate>& raw_gates) {
    Graph g;
    for (auto& gate : raw_gates) {
        gate.type = normalize_gate_type(gate.type);
        g.gate_map[gate.name] = gate; // 先存入閘資料

        // 🛡️ 登記所有輸出線
        for (const auto& out_wire : gate.outputs) {
            g.wire_driver[out_wire] = gate.name;
        }

        // 🛡️ 登記所有輸入線
        for (const auto& in_wire : gate.inputs) {
            g.wire_readers[in_wire].push_back(gate.name);
        }
    }
    return g;
}

static std::vector<std::string> tokenize(const std::string& src) {
    std::vector<std::string> out;
    std::string cur;
    auto flush = [&]() {
        if (!cur.empty()) {
            out.push_back(cur);
            cur.clear();
        }
    };
    for (size_t i = 0; i < src.size(); ++i) {
        char c = src[i];
        if (c == '/' && i + 1 < src.size() && src[i + 1] == '/') {
            while (i < src.size() && src[i] != '\n') ++i;
            continue;
        }
        if (c == '/' && i + 1 < src.size() && src[i + 1] == '*') {
            i += 2;
            while (i + 1 < src.size() && !(src[i] == '*' && src[i + 1] == '/')) ++i;
            i += 1;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(c))) {
            flush();
        } else if (c == '(' || c == ')' || c == ',' || c == ';' || c == '=') {
            flush();
            out.push_back(std::string(1, c));
        } else {
            cur.push_back(c);
        }
    }
    flush();
    return out;
}

static std::string extract_wire(const std::string& raw) {
    size_t p1 = raw.find('(');
    size_t p2 = raw.rfind(')');
    if (p1 != std::string::npos && p2 != std::string::npos && p2 > p1) {
        std::string inner = raw.substr(p1 + 1, p2 - p1 - 1);
        std::string clean;
        for (char c : inner) if (c != ' ' && c != '\t') clean += c;
        return clean;
    }
    std::string clean;
    for (char c : raw) if (c != ' ' && c != '\t') clean += c;
    return clean;
}

// ==========================================
// 終極升級版 Parser (V3)
// ==========================================
static std::pair<std::vector<Gate>, std::unordered_set<std::string>> parse_netlist(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        std::cerr << "error: cannot open " << path << "\n";
        std::exit(1);
    }
    std::string src((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    auto toks = tokenize(src);

    std::vector<Gate> gates;
    std::unordered_set<std::string> true_primary_outputs;

    for (size_t i = 0; i + 2 < toks.size(); ++i) {
        std::string kw = toks[i];

        if (kw == "output") {
            size_t scan_idx = i + 1;
            while (scan_idx < toks.size() && toks[scan_idx] != ";") {
                if (toks[scan_idx] != "wire" && toks[scan_idx] != "reg" && toks[scan_idx].find("[") == std::string::npos) {
                    std::string clean_name = extract_wire(toks[scan_idx]); 
                    if (!clean_name.empty() && clean_name != ",") {
                        true_primary_outputs.insert(clean_name);
                    }
                }
                scan_idx++;
            }
            continue; 
        }

        if (kw == "assign") {
            if (i + 4 < toks.size() && toks[i + 2] == "=" && toks[i + 4] == ";") {
                Gate g;
                g.type = "buf"; 
                g.name = "assign_" + extract_wire(toks[i + 1]);
                g.inputs.push_back(extract_wire(toks[i + 3])); 
                g.outputs.push_back(extract_wire(toks[i + 1])); 
                gates.push_back(std::move(g));
                i += 4; 
            }
            continue;
        }

        if (kw == "module" || kw == "wire" || kw == "input" || kw == "endmodule") {
            continue;
        }

        if (toks[i + 1].empty()) continue;
        if (toks[i + 2] != "(") continue;

        Gate g;
        g.type = normalize_gate_type(toks[i]);
        g.name = toks[i + 1];

        size_t j = i + 3; 
        int depth = 1;
        
        std::vector<std::string> temp_inputs;
        std::vector<std::string> temp_outputs;

        bool is_named_mapping = (j < toks.size() && toks[j].find(".") == 0);

        if (is_named_mapping) {
            std::string current_port = "";
            while (j < toks.size() && depth > 0) {
                const std::string& t = toks[j];
                if (t == "(") { depth++; }
                else if (t == ")") { depth--; }
                else if (t == ",") { }
                else if (t.find(".") == 0) {
                    current_port = t; 
                }
                else {
                    if (depth == 2) {
                        std::string wire_name = extract_wire(t);
                        if (!wire_name.empty()) {
                            std::string p_upper = current_port;
                            std::transform(p_upper.begin(), p_upper.end(), p_upper.begin(), ::toupper);
                            
                            if (p_upper == ".Y" || p_upper == ".Z" || p_upper == ".Q" || p_upper == ".QN" || 
                                p_upper == ".OUT" || p_upper == ".S" || p_upper == ".CO" || 
                                p_upper == ".COUT" || p_upper == ".C" || p_upper == ".P" || p_upper == ".SUM") {
                                temp_outputs.push_back(wire_name);
                            } else {
                                temp_inputs.push_back(wire_name);
                            }
                        }
                    }
                }
                ++j;
            }
        } else {
            std::vector<std::string> raw_pins;
            std::string pin;
            while (j < toks.size() && depth > 0) {
                const std::string& t = toks[j];
                if (t == "(") { depth++; if (depth > 2) pin += t; }
                else if (t == ")") {
                    depth--;
                    if (depth == 0) {
                        if (!pin.empty()) raw_pins.push_back(extract_wire(pin));
                        break;
                    }
                    if (depth >= 1 && !pin.empty()) pin += t;
                }
                else if (t == "," && depth == 1) {
                    if (!pin.empty()) raw_pins.push_back(extract_wire(pin));
                    pin.clear();
                }
                else { pin += t; }
                ++j;
            }

            if (raw_pins.size() > 0) {
                if (g.type == "nand" || g.type == "and" || g.type == "or" || g.type == "nor" || 
                    g.type == "xor" || g.type == "xnor" || g.type == "not" || g.type == "buf") {
                    temp_outputs.push_back(raw_pins.front()); 
                    for (size_t k = 1; k < raw_pins.size(); ++k) temp_inputs.push_back(raw_pins[k]);
                } else {
                    for (size_t k = 0; k < raw_pins.size() - 1; ++k) temp_inputs.push_back(raw_pins[k]);
                    temp_outputs.push_back(raw_pins.back());
                }
            }
        }

        g.inputs = std::move(temp_inputs);
        g.outputs = std::move(temp_outputs);
        gates.push_back(std::move(g));
        
        i = j; 
    }
    return {gates, true_primary_outputs};
}

static void write_no_trojan(const std::string& path) {
    std::ofstream out(path);
    out << "NO_TROJAN\n";
}

static void write_trojaned(const std::string& path, const std::vector<std::string>& gate_names) {
    std::ofstream out(path);
    out << "TROJANED\n";
    out << "TROJAN_GATES\n";
    for (const auto& n : gate_names) out << n << "\n";
    out << "END_TROJAN_GATES\n";
}

// 定義一個回傳結構
struct DetectionResult {
    bool found = false;
    std::vector<std::string> gates;
};

// ==========================================
// 工具函式
// ==========================================
std::string get_logical_driver(const Graph& g, const std::string& start_wire) {
    std::queue<std::string> wire_queue;
    std::unordered_set<std::string> visited;
    
    wire_queue.push(start_wire);
    visited.insert(start_wire);
    
    while (!wire_queue.empty()) {
        std::string curr_wire = wire_queue.front();
        wire_queue.pop();
        
        if (g.wire_driver.find(curr_wire) == g.wire_driver.end()) continue;
        
        std::string driver_id = g.wire_driver.at(curr_wire);
        const Gate& driver_gate = g.gate_map.at(driver_id);
        
        if (driver_gate.type == "buf" || driver_gate.type == "not") {
            if (!driver_gate.inputs.empty()) {
                std::string in_wire = driver_gate.inputs[0];
                if (visited.find(in_wire) == visited.end()) {
                    visited.insert(in_wire);
                    wire_queue.push(in_wire);
                }
            }
        } else {
            return driver_id; 
        }
    }
    return "";
}

std::vector<std::string> get_logical_readers(const Graph& g, const std::string& start_wire) {
    std::vector<std::string> real_readers;
    std::queue<std::string> wire_queue;
    std::unordered_set<std::string> visited_wires;

    wire_queue.push(start_wire);
    visited_wires.insert(start_wire);

    while (!wire_queue.empty()) {
        std::string current_wire = wire_queue.front();
        wire_queue.pop();

        if (g.wire_readers.find(current_wire) == g.wire_readers.end()) continue;

        for (const auto& reader_id : g.wire_readers.at(current_wire)) {
            const Gate& next_gate = g.gate_map.at(reader_id);
            
            if (next_gate.type == "buf" || next_gate.type == "not") {
                for (const auto& next_out_wire : next_gate.outputs) {
                    if (visited_wires.find(next_out_wire) == visited_wires.end()) {
                        visited_wires.insert(next_out_wire);
                        wire_queue.push(next_out_wire);
                    }
                }
            } else {
                real_readers.push_back(reader_id);
            }
        }
    }
    return real_readers;
}



// ==========================================
// 演算法：尋找 Trojan 0 (回歸 71.74% 穩定版)
// ==========================================
bool is_isomorphic_trojan_0(const Graph& g, const std::string& start_dff_id, std::unordered_set<std::string>& out_trojan_cluster) {
    if (g.gate_map.at(start_dff_id).type != "dff") return false;
    
    std::unordered_set<std::string> tap_dffs;
    std::unordered_set<std::string> comb_tree;
    std::queue<std::string> q;

    // 1. 探索大腦：往上游找狀態決定邏輯
    const Gate& start_dff = g.gate_map.at(start_dff_id);
    for (const auto& in_wire : start_dff.inputs) {
        if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
            q.push(g.wire_driver.at(in_wire));
        }
    }

    while (!q.empty()) {
        std::string curr = q.front();
        q.pop();
        if (comb_tree.size() > 30) return false; 

        const Gate& curr_gate = g.gate_map.at(curr);
        if (curr_gate.type == "dff") {
            tap_dffs.insert(curr); 
        } else {
            if (comb_tree.find(curr) == comb_tree.end()) {
                comb_tree.insert(curr);
                for (const auto& in_wire : curr_gate.inputs) {
                    if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                        q.push(g.wire_driver.at(in_wire));
                    }
                }
            }
        }
    }

    // 2. 終極特徵：LFSR 需要從 2 到 8 個 DFF 取得回饋
    if (tap_dffs.size() >= 2 && tap_dffs.size() <= 8) {
        out_trojan_cluster.insert(start_dff_id);
        for (const auto& dff : tap_dffs) out_trojan_cluster.insert(dff);
        for (const auto& gate : comb_tree) out_trojan_cluster.insert(gate);
        
        // 3. 尋找身體 (DFF 貪吃蛇)
        std::string curr_dff = start_dff_id;
        while (true) {
            if (g.gate_map.at(curr_dff).outputs.empty()) break;
            std::string dff_out = g.gate_map.at(curr_dff).outputs[0];
            std::vector<std::string> readers = get_logical_readers(g, dff_out);
            
            std::string next_dff = "";
            for (const auto& r : readers) {
                if (g.gate_map.at(r).type == "dff" && out_trojan_cluster.find(r) == out_trojan_cluster.end()) {
                    next_dff = r;
                    break;
                }
            }
            if (next_dff.empty()) break;
            out_trojan_cluster.insert(next_dff);
            curr_dff = next_dff;
        }
        
        // 4. 尋找獠牙：針對現在抓到的所有木馬細胞，往下游探索 1 層拿 Payload
        std::queue<std::pair<std::string, int>> fq;
        for (const auto& node : out_trojan_cluster) fq.push({node, 0});
        
        while(!fq.empty()) {
            auto [curr, depth] = fq.front();
            fq.pop();
            if (depth >= 1) continue; 
            
            for (const auto& out_wire : g.gate_map.at(curr).outputs) {
                if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                    const auto& readers = g.wire_readers.at(out_wire);
                    if (readers.size() > 12) continue; 

                    for (const auto& r : readers) {
                        if (g.gate_map.at(r).type == "dff") continue; 
                        if (out_trojan_cluster.find(r) == out_trojan_cluster.end()) {
                            out_trojan_cluster.insert(r);
                            fq.push({r, depth + 1});
                        }
                    }
                }
            }
        }
        return true;
    }
    return false;
}

DetectionResult find_trojan_0(const Graph& g) {
    DetectionResult res;
    std::vector<std::unordered_set<std::string>> independent_clusters;

    // 叢集建立與合併
    for (const auto& [id, gate] : g.gate_map) {
        if (gate.type == "dff") {
            std::unordered_set<std::string> local_cluster;
            if (is_isomorphic_trojan_0(g, id, local_cluster)) {
                bool merged = false;
                for (auto& existing_cluster : independent_clusters) {
                    bool overlap = false;
                    for (const auto& node : local_cluster) {
                        if (existing_cluster.find(node) != existing_cluster.end()) { overlap = true; break; }
                    }
                    if (overlap) {
                        for (const auto& node : local_cluster) existing_cluster.insert(node);
                        merged = true; break;
                    }
                }
                if (!merged) independent_clusters.push_back(local_cluster);
            }
        }
    }

    // 🌟 終極防線：面積鎖與外洩鎖
    std::vector<std::unordered_set<std::string>> valid_clusters;
    for (const auto& cluster : independent_clusters) {
        if (cluster.size() > 300) continue; 

        int escape_wires = 0;
        for (const auto& node : cluster) {
            for (const auto& out_wire : g.gate_map.at(node).outputs) {
                bool escapes = false;
                if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                    for (const auto& r : g.wire_readers.at(out_wire)) {
                        if (cluster.find(r) == cluster.end()) {
                            escapes = true; 
                            break;
                        }
                    }
                } else {
                    escapes = true; 
                }
                if (escapes) escape_wires++;
            }
        }

        if (escape_wires <= 15) {
            valid_clusters.push_back(cluster);
        }
    }

    if (valid_clusters.size() > 0 && valid_clusters.size() <= 3) {
        res.found = true;
        std::unordered_set<std::string> final_gates;
        for (const auto& cluster : valid_clusters) {
            for (const auto& node : cluster) {
                final_gates.insert(node);
            }
        }
        res.gates.assign(final_gates.begin(), final_gates.end());
        return res;
    }
    return res; 
}


// ==========================================
// 演算法：尋找 Trojan 1
// ==========================================
bool is_isomorphic_trojan_1(const Graph& g, const std::string& start_dff_id, std::unordered_set<std::string>& out_cluster) {
    if (g.gate_map.at(start_dff_id).type != "dff" || g.gate_map.at(start_dff_id).outputs.empty()) return false;
    
    std::string dff_out = g.gate_map.at(start_dff_id).outputs[0];
    std::vector<std::string> logical_readers = get_logical_readers(g, dff_out);
    bool is_counter_bit = false;

    out_cluster.insert(start_dff_id);

    for (const auto& reader_id : logical_readers) {
        std::string t = g.gate_map.at(reader_id).type;
        if (t == "xor" || t == "xnor" || t == "and" || t == "nand" || t == "or" || t == "nor") {
            out_cluster.insert(reader_id); 
            
            for (const auto& logic_out : g.gate_map.at(reader_id).outputs) {
                std::vector<std::string> next_readers = get_logical_readers(g, logic_out);
                for (const auto& nr : next_readers) {
                    if (g.gate_map.at(nr).type == "dff") {
                        is_counter_bit = true;
                        out_cluster.insert(nr);
                    }
                }
            }
        }
    }
    return is_counter_bit;
}

DetectionResult find_trojan_1(const Graph& g) {
    DetectionResult res;
    std::vector<std::unordered_set<std::string>> independent_clusters;

    for (const auto& [id, gate] : g.gate_map) {
        if (gate.type == "dff") {
            std::unordered_set<std::string> local_cluster;
            std::queue<std::pair<std::string, int>> q;
            
            q.push({id, 0});
            local_cluster.insert(id);

            while (!q.empty()) {
                auto [curr, depth] = q.front();
                q.pop();
                
                if (depth >= 5) continue; 
                if (local_cluster.size() > 300) break; 
                const Gate& curr_gate = g.gate_map.at(curr);
                for (const auto& in_wire : curr_gate.inputs) { 
                    // 1. 確保這條輸入線有來源 (不是懸空的)
                    if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                        std::string driver = g.wire_driver.at(in_wire);
                        
                        // 2. 確保這個來源還沒被走訪過
                        if (local_cluster.find(driver) == local_cluster.end()) {
                            
                            // 3. 判斷是不是 DFF
                            if (g.gate_map.at(driver).type == "dff") {
                                local_cluster.insert(driver);
                                // ✅ 正確：撞到 DFF 就當作島嶼邊界，絕對不要把它 push 進 Queue 裡擴散！
                            } else {
                                local_cluster.insert(driver);
                                q.push({driver, depth + 1}); // 是一般邏輯閘，繼續往上游探索
                            }
                        }
                    }
                }
            }

            bool merged = false;
            for (auto& existing_cluster : independent_clusters) {
                bool overlap = false;
                for (const auto& node : local_cluster) {
                    if (existing_cluster.find(node) != existing_cluster.end()) { overlap = true; break; }
                }
                if (overlap) {
                    for (const auto& node : local_cluster) existing_cluster.insert(node);
                    merged = true; break;
                }
            }
            if (!merged) independent_clusters.push_back(local_cluster);
        }
    }

    std::vector<std::unordered_set<std::string>> valid_clusters;
    for (const auto& cluster : independent_clusters) {
        
        // 🌟 防禦 1：最小與最大體積鎖
        // Trojan 0 包含 LFSR 與 64-bit Payload，整座島絕對大於 40 顆閘。
        // 系統正常的 3-bit/4-bit 小狀態機通常只有 10~30 顆閘，這裡直接秒殺！
        if (cluster.size() < 40 || cluster.size() > 300) continue; 

        // 🌟 防禦 2：密碼學特徵鎖 (XOR Count) - 這是殺死誤判的核武！
        // Trojan 0 的 Payload 是一大票 XOR 閘。
        // 我們保守要求島內至少要有 8 顆 XOR/XNOR 閘。一般的控制邏輯絕對達不到這個數量。
        int xor_count = 0;
        for (const auto& node : cluster) {
            std::string type = g.gate_map.at(node).type;
            if (type == "xor" || type == "xnor") {
                xor_count++;
            }
        }
        if (xor_count < 8) continue; // 缺乏密碼學特徵，絕對不是 Trojan 0

        int escape_wires = 0;
        for (const auto& node : cluster) {
            for (const auto& out_wire : g.gate_map.at(node).outputs) {
                bool escapes = false;
                if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                    for (const auto& r : g.wire_readers.at(out_wire)) {
                        if (cluster.find(r) == cluster.end()) {
                            escapes = true; 
                            break;
                        }
                    }
                } else {
                    escapes = true; 
                }
                if (escapes) escape_wires++;
            }
        }

        // LFSR 的外洩線鎖 (保留原本完美的 15 根設定)
        if (escape_wires <= 15) {
            valid_clusters.push_back(cluster);
        }
    }

    if (valid_clusters.size() > 0 && valid_clusters.size() <= 3) {
        res.found = true;
        std::unordered_set<std::string> final_gates;
        for (const auto& cluster : valid_clusters) {
            for (const auto& node : cluster) final_gates.insert(node);
        }
        res.gates.assign(final_gates.begin(), final_gates.end());
        return res;
    }
    return res;
}


// ==========================================
// 演算法：尋找 Trojan 2
// ==========================================
bool is_isomorphic_trojan_2(const Graph& g, const std::string& start_dff_id, std::unordered_set<std::string>& out_trojan_cluster) {
    if (g.gate_map.at(start_dff_id).type != "dff") return false;

    std::vector<std::string> dff_chain;
    std::string curr_dff = start_dff_id;
    std::unordered_set<std::string> visited_dffs;

    while (true) {
        dff_chain.push_back(curr_dff);
        visited_dffs.insert(curr_dff);
        
        if (g.gate_map.at(curr_dff).outputs.empty()) break;
        std::string dff_out = g.gate_map.at(curr_dff).outputs[0];
        std::vector<std::string> logical_readers = get_logical_readers(g, dff_out);
        
        std::string next_dff = "";
        for (const auto& reader_id : logical_readers) {
            if (g.gate_map.at(reader_id).type == "dff") {
                next_dff = reader_id;
                break; 
            }
        }
        
        if (next_dff.empty() || visited_dffs.find(next_dff) != visited_dffs.end()) break;
        curr_dff = next_dff;
    }

    if (dff_chain.size() >= 8 && dff_chain.size() <= 64) {
        int tap_count = 0;
        for (size_t i = 0; i < dff_chain.size() - 1; ++i) {
            if (g.gate_map.at(dff_chain[i]).outputs.empty()) continue;
            std::string dff_out = g.gate_map.at(dff_chain[i]).outputs[0];
            if (g.wire_readers.find(dff_out) != g.wire_readers.end()) {
                if (g.wire_readers.at(dff_out).size() >= 2) tap_count++;
            }
        }

        if (tap_count < dff_chain.size() / 3) return false; 

        std::string tail_dff = dff_chain.back();
        if (g.gate_map.at(tail_dff).outputs.empty()) return false;
        std::string tail_out = g.gate_map.at(tail_dff).outputs[0];
        int tail_fanout = 0;
        if (g.wire_readers.find(tail_out) != g.wire_readers.end()) {
            tail_fanout = g.wire_readers.at(tail_out).size();
        }
        if (tail_fanout > 4) return false; 

        std::queue<std::pair<std::string, int>> q;
        for (const std::string& chain_dff : dff_chain) {
            q.push({chain_dff, 0});
            out_trojan_cluster.insert(chain_dff);
        }
        
        while (!q.empty()) {
            auto [curr_id, depth] = q.front();
            q.pop();
            if (depth >= 5) continue;
            
            const Gate& curr_gate = g.gate_map.at(curr_id);
            for (const auto& curr_out : curr_gate.outputs) {
                if (g.wire_readers.find(curr_out) != g.wire_readers.end()) {
                    const auto& readers = g.wire_readers.at(curr_out);
                    if (readers.size() > 8) continue; 

                    for (const auto& r_id : readers) {
                        if (g.gate_map.at(r_id).type != "dff" && out_trojan_cluster.find(r_id) == out_trojan_cluster.end()) {
                            out_trojan_cluster.insert(r_id);
                            q.push({r_id, depth + 1});
                        }
                    }
                }
            }
            
            for (const auto& in_wire : curr_gate.inputs) {
                if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                    std::string driver_id = g.wire_driver.at(in_wire);
                    if (g.gate_map.at(driver_id).type != "dff" && out_trojan_cluster.find(driver_id) == out_trojan_cluster.end()) {
                        out_trojan_cluster.insert(driver_id);
                        q.push({driver_id, depth + 1});
                    }
                }
            }
        }
        return true;
    }
    return false;
}

DetectionResult find_trojan_2(const Graph& g) {
    DetectionResult res;
    std::unordered_set<std::string> trojan_cluster;

    for (const auto& [id, gate] : g.gate_map) {
        if (gate.type == "dff") {
            if (is_isomorphic_trojan_2(g, id, trojan_cluster)) {
                res.found = true;
                res.gates.assign(trojan_cluster.begin(), trojan_cluster.end());
                return res;
            }
        }
    }
    return res;
}


// ==========================================
// 演算法：尋找 Trojan 3
// ==========================================
DetectionResult find_trojan_3(const Graph& g) {
    DetectionResult res;
    std::vector<std::unordered_set<std::string>> independent_clusters;

    for (const auto& [id, gate] : g.gate_map) {
        if (gate.type == "dff") {
            std::unordered_set<std::string> local_cluster;
            std::queue<std::pair<std::string, int>> q;
            q.push({id, 0});
            local_cluster.insert(id);

            while (!q.empty()) {
                auto [curr, depth] = q.front();
                q.pop();

                if (depth >= 5) continue; 
                if (local_cluster.size() > 80) break; 

                const Gate& curr_gate = g.gate_map.at(curr);
                for (const auto& in_wire : curr_gate.inputs) { 
                    // 🛡️ 高扇出防火牆：斬斷 Clock, Reset, Enable 的污染
                    if (g.wire_readers.find(in_wire) != g.wire_readers.end()) {
                        if (g.wire_readers.at(in_wire).size() > 20) continue; 
                    }

                    // 1. 確保這條輸入線有來源 (不是懸空的)
                    if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                        std::string driver = g.wire_driver.at(in_wire);
                        
                        // 2. 確保這個來源還沒被走訪過
                        if (local_cluster.find(driver) == local_cluster.end()) {
                            
                            // 3. 判斷是不是 DFF
                            if (g.gate_map.at(driver).type == "dff") {
                                local_cluster.insert(driver);
                                // ✅ 正確：不 push，停止向上游蔓延
                            } else {
                                local_cluster.insert(driver);
                                q.push({driver, depth + 1}); // 是一般邏輯閘，繼續往上游探索
                            }
                        }
                    }
                }
            }
            
            bool merged = false;
            for (auto& existing_cluster : independent_clusters) {
                bool overlap = false;
                for (const auto& node : local_cluster) {
                    if (existing_cluster.find(node) != existing_cluster.end()) { overlap = true; break; }
                }
                if (overlap) {
                    for (const auto& node : local_cluster) existing_cluster.insert(node);
                    merged = true; break;
                }
            }
            if (!merged) independent_clusters.push_back(local_cluster);
        }
    }

    std::unordered_set<std::string> trojan_gates;
    bool t3_found = false;

    for (const auto& cluster : independent_clusters) {
        int dff_count = 0;
        for (const auto& node : cluster) {
            if (g.gate_map.at(node).type == "dff") dff_count++;
        }

        if (dff_count < 7 || dff_count > 9) continue;
        if (cluster.size() > 80) continue;

        int escape_wires = 0;
        std::vector<std::string> escape_nodes;
        
        for (const auto& node : cluster) {
            for (const auto& out_wire : g.gate_map.at(node).outputs) {
                bool escapes = false;
                if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                    for (const auto& r : g.wire_readers.at(out_wire)) {
                        if (cluster.find(r) == cluster.end()) { 
                            escapes = true; 
                            escape_nodes.push_back(node);
                            break; 
                        }
                    }
                } else {
                    escapes = true; 
                }
                if (escapes) escape_wires++;
            }
        }

        if (escape_wires == 1 || escape_wires == 2) {
            t3_found = true;
            for (const auto& node : cluster) trojan_gates.insert(node);

            std::queue<std::pair<std::string, int>> fq;
            for (const auto& enode : escape_nodes) {
                fq.push({enode, 0});
            }

            while (!fq.empty()) {
                auto [curr, depth] = fq.front();
                fq.pop();

                if (depth >= 4) continue; 
                
                for (const auto& out_wire : g.gate_map.at(curr).outputs) {
                    if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                        for (const auto& r : g.wire_readers.at(out_wire)) {
                            if (g.gate_map.at(r).type == "dff") continue; 
                            if (trojan_gates.find(r) == trojan_gates.end()) {
                                trojan_gates.insert(r);
                                fq.push({r, depth + 1});
                            }
                        }
                    }
                }
            }
        }
    }

    if (t3_found) {
        res.found = true;
        res.gates.assign(trojan_gates.begin(), trojan_gates.end());
    }
    return res;
}


// ==========================================
// 演算法：尋找 Trojan 4
// ==========================================
bool is_isomorphic_trojan_4(const Graph& g, const std::string& start_dff_id, std::unordered_set<std::string>& out_trojan_cluster) {
    if (g.gate_map.at(start_dff_id).type != "dff") return false;

    std::vector<std::string> dff_chain;
    std::string curr_dff = start_dff_id;
    std::unordered_set<std::string> visited_dffs;

    while (true) {
        dff_chain.push_back(curr_dff);
        visited_dffs.insert(curr_dff);
        
        if (g.gate_map.at(curr_dff).outputs.empty()) break;
        std::string dff_out = g.gate_map.at(curr_dff).outputs[0];
        std::vector<std::string> logical_readers = get_logical_readers(g, dff_out);
        
        std::string next_dff = "";
        for (const auto& reader_id : logical_readers) {
            if (g.gate_map.at(reader_id).type == "dff") {
                next_dff = reader_id;
                break; 
            }
        }
        
        if (next_dff.empty() || visited_dffs.find(next_dff) != visited_dffs.end()) break;
        curr_dff = next_dff;
    }

    if (dff_chain.size() >= 3 && dff_chain.size() <= 64) {
        std::unordered_set<std::string> payload_gates;
        for (const std::string& dff : dff_chain) {
            if (g.gate_map.at(dff).outputs.empty()) continue;
            std::string out_wire = g.gate_map.at(dff).outputs[0];
            std::vector<std::string> logical_readers = get_logical_readers(g, out_wire);
            
            for (const auto& r_id : logical_readers) {
                if (visited_dffs.find(r_id) == visited_dffs.end()) {
                    payload_gates.insert(r_id);
                }
            }
        }

        if (payload_gates.size() >= 32) {
            for (const auto& dff : dff_chain) out_trojan_cluster.insert(dff);
            for (const auto& gate : payload_gates) out_trojan_cluster.insert(gate);
            return true;
        }
    }
    return false;
}

DetectionResult find_trojan_4(const Graph& g) {
    DetectionResult res;
    std::unordered_set<std::string> anchors;

    for (const auto& [id, gate] : g.gate_map) {
        if (gate.type == "dff") {
            if (is_isomorphic_trojan_4(g, id, anchors)) {
                res.found = true;
                res.gates.assign(anchors.begin(), anchors.end());
                return res;
            }
        }
    }
    return res;
}


// ==========================================
// 演算法：尋找 Trojan 5
// ==========================================
bool is_isomorphic_trojan_5(const Graph& g, const std::string& candidate_id, std::unordered_set<std::string>& out_trojan_cluster) {
    const Gate& candidate = g.gate_map.at(candidate_id);
    
    if (candidate.type != "xor" && candidate.type != "xnor" && candidate.type != "mux") return false;

    for (const auto& in_wire : candidate.inputs) {
        std::string driver_id = get_logical_driver(g, in_wire);
        if (driver_id.empty()) continue;
        if (g.gate_map.at(driver_id).type == "dff") continue;

        std::queue<std::string> q;
        std::unordered_set<std::string> comb_tree;
        
        q.push(driver_id);
        comb_tree.insert(driver_id);
        comb_tree.insert(candidate_id); 

        while (!q.empty()) {
            std::string curr = q.front();
            q.pop();

            const Gate& curr_gate = g.gate_map.at(curr);
            for (const auto& up_wire : curr_gate.inputs) {
                std::string up_drv = get_logical_driver(g, up_wire);
                if (up_drv.empty()) continue;

                if (g.gate_map.at(up_drv).type != "dff") {
                    if (comb_tree.find(up_drv) == comb_tree.end()) {
                        comb_tree.insert(up_drv);
                        q.push(up_drv);
                    }
                }
            }
        }

        if (comb_tree.size() > 15 && comb_tree.size() < 100) {
            int xor_count = 0;
            int internal_fanout_escapes = 0;

            for (const auto& node : comb_tree) {
                if (node == candidate_id) continue; 

                std::string t = g.gate_map.at(node).type;
                if (t == "xor" || t == "xnor") xor_count++;

                if (node == driver_id) continue; 
                for (const auto& out_wire : g.gate_map.at(node).outputs) {
                    if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                        for (const auto& r : g.wire_readers.at(out_wire)) {
                            if (comb_tree.find(r) == comb_tree.end() && r != candidate_id) {
                                internal_fanout_escapes++;
                            }
                        }
                    } else {
                        internal_fanout_escapes++; 
                    }
                }
            }

            if (xor_count > 3) return false;
            if (internal_fanout_escapes > 2) return false;

            if (!g.gate_map.at(driver_id).outputs.empty()) {
                std::string trigger_wire = g.gate_map.at(driver_id).outputs[0];
                if (g.wire_readers.find(trigger_wire) != g.wire_readers.end()) {
                    if (g.wire_readers.at(trigger_wire).size() <= 2) {
                        out_trojan_cluster = comb_tree;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

DetectionResult find_trojan_5(const Graph& g) {
    DetectionResult res;
    std::unordered_set<std::string> final_anchors;
    int match_count = 0;

    for (const auto& [id, gate] : g.gate_map) {
        std::unordered_set<std::string> local_anchors;
        if (is_isomorphic_trojan_5(g, id, local_anchors)) {
            match_count++;
            if (match_count == 1) final_anchors = local_anchors; 
        }
    }

    if (match_count > 0 && match_count <= 8) {
        res.found = true;
        res.gates.assign(final_anchors.begin(), final_anchors.end());
        return res;
    }
    return res; 
}


// ==========================================
// 演算法：尋找 Trojan 6
// ==========================================
bool is_isomorphic_trojan_6(const Graph& g, const std::string& candidate_id, std::unordered_set<std::string>& out_trojan_cluster) {
    const Gate& candidate = g.gate_map.at(candidate_id);

    if (candidate.type == "dff" || candidate.type == "buf" || candidate.type == "not") return false;
    if (candidate.outputs.empty()) return false;

    std::string trigger_wire = candidate.outputs[0];
    std::vector<std::string> logical_readers = get_logical_readers(g, trigger_wire);

    if (logical_readers.size() >= 1 && logical_readers.size() <= 8) {
        std::queue<std::string> q;
        std::unordered_set<std::string> comb_tree;
        std::unordered_set<std::string> upstream_sources; 

        q.push(candidate_id);
        comb_tree.insert(candidate_id);

        while (!q.empty()) {
            std::string curr = q.front();
            q.pop();
            const Gate& curr_gate = g.gate_map.at(curr);

            for (const auto& in_wire : curr_gate.inputs) {
                if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                    std::string driver_id = g.wire_driver.at(in_wire);
                    if (g.gate_map.at(driver_id).type == "dff") {
                        upstream_sources.insert(driver_id); 
                    } else {
                        if (comb_tree.find(driver_id) == comb_tree.end()) {
                            comb_tree.insert(driver_id);
                            q.push(driver_id);
                        }
                    }
                } else {
                    upstream_sources.insert(in_wire);
                }
            }
        }

        if (comb_tree.size() >= 25 && comb_tree.size() <= 120) {
            if (upstream_sources.size() < 16) return false;

            int internal_fanout_escapes = 0;
            for (const auto& node : comb_tree) {
                if (node == candidate_id) continue; 
                
                for (const auto& out_wire : g.gate_map.at(node).outputs) {
                    if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                        for (const auto& r : g.wire_readers.at(out_wire)) {
                            if (comb_tree.find(r) == comb_tree.end()) {
                                internal_fanout_escapes++;
                            }
                        }
                    } else {
                        internal_fanout_escapes++; 
                    }
                }
            }

            if (internal_fanout_escapes > 2) return false;
            out_trojan_cluster = comb_tree;
            return true;
        }
    }
    return false;
}

DetectionResult find_trojan_6(const Graph& g) {
    DetectionResult res;
    std::unordered_set<std::string> final_anchors;
    int match_count = 0;

    for (const auto& [id, gate] : g.gate_map) {
        std::unordered_set<std::string> local_anchors;
        if (is_isomorphic_trojan_6(g, id, local_anchors)) {
            match_count++;
            if (match_count == 1) final_anchors = local_anchors; 
        }
    }

    if (match_count > 0 && match_count <= 8) {
        res.found = true;
        res.gates.assign(final_anchors.begin(), final_anchors.end());
        return res;
    }
    return res;
}


// ==========================================
// 演算法：尋找 Trojan 7
// ==========================================
bool is_isomorphic_trojan_7(const Graph& g, const std::string& candidate_id, std::unordered_set<std::string>& out_trojan_cluster) {
    const Gate& candidate = g.gate_map.at(candidate_id);

    if (candidate.type == "dff" || candidate.type == "buf" || candidate.type == "not") return false;
    if (candidate.outputs.empty()) return false;

    std::string trigger_wire = candidate.outputs[0];
    std::vector<std::string> logical_readers = get_logical_readers(g, trigger_wire);

    if (logical_readers.size() >= 1 && logical_readers.size() <= 8) {
        std::queue<std::string> q;
        std::unordered_set<std::string> comb_tree;
        std::unordered_set<std::string> upstream_sources; 

        q.push(candidate_id);
        comb_tree.insert(candidate_id);

        while (!q.empty()) {
            std::string curr = q.front();
            q.pop();
            const Gate& curr_gate = g.gate_map.at(curr);

            for (const auto& in_wire : curr_gate.inputs) {
                if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                    std::string driver_id = g.wire_driver.at(in_wire);
                    if (g.gate_map.at(driver_id).type == "dff") {
                        upstream_sources.insert(driver_id); 
                    } else {
                        if (comb_tree.find(driver_id) == comb_tree.end()) {
                            comb_tree.insert(driver_id);
                            q.push(driver_id);
                        }
                    }
                } else {
                    upstream_sources.insert(in_wire);
                }
            }
        }

        if (comb_tree.size() >= 40 && comb_tree.size() <= 150) {
            if (upstream_sources.size() < 32) return false;

            int internal_fanout_escapes = 0;
            for (const auto& node : comb_tree) {
                if (node == candidate_id) continue; 
                
                for (const auto& out_wire : g.gate_map.at(node).outputs) {
                    if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                        for (const auto& r : g.wire_readers.at(out_wire)) {
                            if (comb_tree.find(r) == comb_tree.end()) {
                                internal_fanout_escapes++;
                            }
                        }
                    } else {
                        internal_fanout_escapes++; 
                    }
                }
            }

            if (internal_fanout_escapes > 4) return false;
            out_trojan_cluster = comb_tree; 
            return true;
        }
    }
    return false;
}

DetectionResult find_trojan_7(const Graph& g) {
    DetectionResult res;
    std::unordered_set<std::string> final_anchors;
    int match_count = 0;

    for (const auto& [id, gate] : g.gate_map) {
        std::unordered_set<std::string> local_anchors;
        if (is_isomorphic_trojan_7(g, id, local_anchors)) {
            match_count++;
            if (match_count == 1) final_anchors = local_anchors; 
        }
    }

    if (match_count > 0 && match_count <= 8) {
        res.found = true;
        res.gates.assign(final_anchors.begin(), final_anchors.end());
        return res;
    }
    return res; 
}


// ==========================================
// 演算法：尋找 Trojan 8
// ==========================================
bool is_massive_combinational_island(const Graph& g, const std::string& start_id, std::unordered_set<std::string>& out_cluster, std::unordered_set<std::string>& global_visited) {
    if (g.gate_map.at(start_id).type == "dff") return false;

    std::queue<std::string> q;
    std::unordered_set<std::string> local_cluster;

    q.push(start_id);
    local_cluster.insert(start_id);

    while(!q.empty()) {
        std::string curr = q.front();
        q.pop();

        const Gate& curr_gate = g.gate_map.at(curr);

        for (const auto& out_wire : curr_gate.outputs) {
            if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                for (const auto& r : g.wire_readers.at(out_wire)) {
                    if (g.gate_map.at(r).type != "dff" && local_cluster.find(r) == local_cluster.end()) {
                        local_cluster.insert(r);
                        q.push(r);
                    }
                }
            }
        }

        for (const auto& in_wire : curr_gate.inputs) {
            if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                std::string d = g.wire_driver.at(in_wire);
                if (g.gate_map.at(d).type != "dff" && local_cluster.find(d) == local_cluster.end()) {
                    local_cluster.insert(d);
                    q.push(d);
                }
            }
        }
    }

    for (const auto& node : local_cluster) {
        global_visited.insert(node);
    }

    bool has_dff = false;
    for (const auto& [id, gate] : g.gate_map) {
        if (gate.type == "dff") { has_dff = true; break; }
    }
    if (!has_dff) return false;

    if (local_cluster.size() > 800 && local_cluster.size() < g.gate_map.size() * 0.25) {
        std::unordered_set<std::string> outgoing_wires;
        for (const auto& node : local_cluster) {
            for (const auto& out_wire : g.gate_map.at(node).outputs) {
                bool goes_outside = false;
                if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                    for (const auto& r : g.wire_readers.at(out_wire)) {
                        if (local_cluster.find(r) == local_cluster.end()) {
                            goes_outside = true; break; 
                        }
                    }
                } else { goes_outside = true; }
                if (goes_outside) outgoing_wires.insert(out_wire);
            }
        }

        bool has_infection_point = false;
        for (const auto& out_wire : outgoing_wires) {
            if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                for (const auto& r_id : g.wire_readers.at(out_wire)) {
                    const Gate& reader_gate = g.gate_map.at(r_id);
                    if (reader_gate.type == "dff") continue;

                    bool mixes_with_normal_data = false;
                    for (const auto& in_wire : reader_gate.inputs) {
                        if (in_wire != out_wire) { 
                            if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                                std::string sibling_driver = g.wire_driver.at(in_wire);
                                if (local_cluster.find(sibling_driver) == local_cluster.end()) {
                                    mixes_with_normal_data = true;
                                    break;
                                }
                            } else {
                                mixes_with_normal_data = true;
                                break;
                            }
                        }
                    }
                    if (mixes_with_normal_data) {
                        has_infection_point = true;
                        break;
                    }
                }
            }
            if (has_infection_point) break;
        }

        if (!has_infection_point) return false;
        out_cluster = local_cluster;
        return true;
    }
    return false;
}

DetectionResult find_trojan_8(const Graph& g) {
    DetectionResult res;
    std::unordered_set<std::string> global_visited;
    std::unordered_set<std::string> trojan_cluster;

    for (const auto& [id, gate] : g.gate_map) {
        if (global_visited.find(id) != global_visited.end()) continue;
        if (is_massive_combinational_island(g, id, trojan_cluster, global_visited)) {
            res.found = true;
            res.gates.assign(trojan_cluster.begin(), trojan_cluster.end());
            return res;
        }
    }
    return res;
}


// ==========================================
// 演算法 V2：尋找 Trojan 9
// ==========================================
bool is_isomorphic_trojan_9(const Graph& g, 
                            const std::string& start_id, 
                            std::unordered_set<std::string>& out_cluster, 
                            std::unordered_set<std::string>& global_visited,
                            const std::unordered_set<std::string>& true_primary_outputs) { 
    
    if (g.gate_map.at(start_id).type == "dff") return false;

    std::queue<std::string> q; 
    std::unordered_set<std::string> local_cluster;
    
    q.push(start_id);
    local_cluster.insert(start_id);
    global_visited.insert(start_id); // 🔥 立即標記，拒絕重複走訪！

    int xor_and_count = 0;    

    while(!q.empty()) {
        std::string curr = q.front();
        q.pop();

        const Gate& curr_gate = g.gate_map.at(curr);
        
        if (curr_gate.type == "xor" || curr_gate.type == "xnor" || 
            curr_gate.type == "and" || curr_gate.type == "nand") {
            xor_and_count++;
        }

        // 往下游
        for (const auto& out_wire : curr_gate.outputs) {
            if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                for (const auto& r : g.wire_readers.at(out_wire)) {
                    if (g.gate_map.at(r).type != "dff" && local_cluster.find(r) == local_cluster.end()) {
                        local_cluster.insert(r);
                        global_visited.insert(r); // 🔥 立即標記
                        q.push(r);
                    }
                }
            }
        }

        // 往上游
        for (const auto& in_wire : curr_gate.inputs) {
            if (g.wire_driver.find(in_wire) != g.wire_driver.end()) {
                std::string d = g.wire_driver.at(in_wire);
                if (g.gate_map.at(d).type != "dff" && local_cluster.find(d) == local_cluster.end()) {
                    local_cluster.insert(d);
                    global_visited.insert(d); // 🔥 立即標記
                    q.push(d);
                }
            }
        }
    }

    if (local_cluster.size() >= 100 && local_cluster.size() <= 800) {
        float arithmetic_ratio = static_cast<float>(xor_and_count) / local_cluster.size();
        if (arithmetic_ratio < 0.25f) return false; 

        std::unordered_set<std::string> driven_dffs;
        int primary_outputs = 0;

        for (const auto& node : local_cluster) {
            for (const auto& out_wire : g.gate_map.at(node).outputs) {
                if (g.wire_readers.find(out_wire) != g.wire_readers.end()) {
                    for (const auto& r : g.wire_readers.at(out_wire)) {
                        if (g.gate_map.at(r).type == "dff") driven_dffs.insert(r);
                    }
                } 
                if (true_primary_outputs.find(out_wire) != true_primary_outputs.end()) {
                    primary_outputs++; 
                }
            }
        }

        int total_data_width = driven_dffs.size() + primary_outputs;
        if (total_data_width < 12 || total_data_width > 24) return false; 

        out_cluster = local_cluster;
        return true;
    }
    return false;
}

DetectionResult find_trojan_9(const Graph& g, const std::unordered_set<std::string>& true_primary_outputs) {
    DetectionResult res;
    std::unordered_set<std::string> global_visited;
    std::unordered_set<std::string> trojan_cluster;

    for (const auto& [id, gate] : g.gate_map) {
        if (global_visited.find(id) != global_visited.end()) continue;
        
        if (is_isomorphic_trojan_9(g, id, trojan_cluster, global_visited, true_primary_outputs)) {
            res.found = true;
            res.gates.assign(trojan_cluster.begin(), trojan_cluster.end());
            return res; 
        }
    }
    return res;
}


// ==========================================
// 主程式入口
// ==========================================
int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <design.v> <output.txt>\n";
        return 1;
    }
    const std::string design_path = argv[1];
    const std::string out_path = argv[2];
    
    // 1. 呼叫終極 Parser，同時接收 gates 與 true_primary_outputs
    auto [raw_gates, true_primary_outputs] = parse_netlist(design_path);

    // 2. 建立圖形 (Graph)
    Graph graph = build_graph(raw_gates);

    // ========================================================
    // 3. 多執行緒並行掃描 (Multi-threading Signature Matching)
    // ========================================================
    // 全部統一使用 graph 變數！
    auto future_t0 = std::async(std::launch::async, find_trojan_0, std::cref(graph));
    auto future_t1 = std::async(std::launch::async, find_trojan_1, std::cref(graph));
    auto future_t2 = std::async(std::launch::async, find_trojan_2, std::cref(graph));
    auto future_t3 = std::async(std::launch::async, find_trojan_3, std::cref(graph));
    auto future_t4 = std::async(std::launch::async, find_trojan_4, std::cref(graph));
    auto future_t5 = std::async(std::launch::async, find_trojan_5, std::cref(graph));
    auto future_t6 = std::async(std::launch::async, find_trojan_6, std::cref(graph));
    auto future_t7 = std::async(std::launch::async, find_trojan_7, std::cref(graph));
    auto future_t8 = std::async(std::launch::async, find_trojan_8, std::cref(graph));
    
    // Trojan 9 需要傳入 true_primary_outputs 作為第二個參數
    auto future_t9 = std::async(std::launch::async, find_trojan_9, std::cref(graph), std::cref(true_primary_outputs));

    // 等待所有執行緒跑完並取得結果
    DetectionResult res0 = future_t0.get();
    DetectionResult res1 = future_t1.get();
    DetectionResult res2 = future_t2.get();
    DetectionResult res3 = future_t3.get();
    DetectionResult res4 = future_t4.get();
    DetectionResult res5 = future_t5.get();
    DetectionResult res6 = future_t6.get();
    DetectionResult res7 = future_t7.get();
    DetectionResult res8 = future_t8.get();
    DetectionResult res9 = future_t9.get();

    // ========================================================
    // 4. 匯總結果
    // ========================================================
    std::vector<std::string> suspects;
    int detected_type = -1;
    DetectionResult res;
    
    if (res0.found) {
        suspects = res0.gates;
        detected_type = 0;
        res = res0;
    } else if (res1.found) {
        suspects = res1.gates;
        detected_type = 1;
        res = res1;
    } else if (res2.found) {
        suspects = res2.gates;
        detected_type = 2;
        res = res2;
    } else if (res3.found) {
        suspects = res3.gates;
        detected_type = 3;
        res = res3;
    } else if (res4.found) {
        suspects = res4.gates;
        detected_type = 4;
        res = res4;
    } else if (res5.found) {
        suspects = res5.gates;
        detected_type = 5;
        res = res5;
    } else if (res6.found) {
        suspects = res6.gates;
        detected_type = 6;
        res = res6;
    } else if (res7.found) {
        suspects = res7.gates;
        detected_type = 7;
        res = res7;
    } else if (res8.found) {
        suspects = res8.gates;
        detected_type = 8;
        res = res8;
    } else if (res9.found) {
        suspects = res9.gates;
        detected_type = 9;
        res = res9;
    }

    // ========================================================
    // 5. 寫入輸出檔案
    // ========================================================
    if (suspects.empty()) {
        write_no_trojan(out_path);
    } else {
        write_trojaned(out_path, suspects);
    }

//    if (res.found) {
//        std::cerr << ">>> [追蹤] 觸發了 Trojan " << detected_type 
//                  << " 演算法！共收網了 " << res.gates.size() << " 顆邏輯閘。\n";
//    } else {
//        std::cerr << ">>> [追蹤] 安全，NO_TROJAN\n";
//    }

    return 0;
}