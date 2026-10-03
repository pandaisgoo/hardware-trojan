`timescale 1ns / 1ps

/* one AES round for every two clock cycles */
module one_round (clk, state_in, key, state_out);
    input              clk;
    input      [127:0] state_in, key;
    output reg [127:0] state_out;

    wire [127:0] sb_out;  // SubBytes 
    wire [127:0] sr_out;  // ShiftRows 
    wire [127:0] mc_out;  // MixColumns 
    wire [127:0] ark_out; // AddRoundKey 

    S4 s_box_0 (clk, state_in[127:96], sb_out[127:96]);
    S4 s_box_1 (clk, state_in[95:64],  sb_out[95:64]);
    S4 s_box_2 (clk, state_in[63:32],  sb_out[63:32]);
    S4 s_box_3 (clk, state_in[31:0],   sb_out[31:0]);

    assign sr_out[127:96] = {sb_out[127:120], sb_out[87:80],   sb_out[47:40],   sb_out[7:0]};
    assign sr_out[95:64]  = {sb_out[95:88],   sb_out[55:48],   sb_out[15:8],    sb_out[103:96]};
    assign sr_out[63:32]  = {sb_out[63:56],   sb_out[23:16],   sb_out[111:104], sb_out[71:64]};
    assign sr_out[31:0]   = {sb_out[31:24],   sb_out[119:112], sb_out[79:72],   sb_out[39:32]};

    assign mc_out[127:96] = mix_column(sr_out[127:96]);
    assign mc_out[95:64]  = mix_column(sr_out[95:64]);
    assign mc_out[63:32]  = mix_column(sr_out[63:32]);
    assign mc_out[31:0]   = mix_column(sr_out[31:0]);

    assign ark_out = mc_out ^ key;

    always @ (posedge clk) begin
        state_out <= ark_out;
    end

    function [31:0] mix_column;
        input [31:0] col_in;
        reg [7:0] a0, a1, a2, a3;
        reg [7:0] r0, r1, r2, r3;
        begin
            a0 = col_in[31:24];
            a1 = col_in[23:16];
            a2 = col_in[15:8];
            a3 = col_in[7:0];

            r0 = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            r1 = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            r2 = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            r3 = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);

            mix_column = {r0, r1, r2, r3};
        end
    endfunction

    function [7:0] xtime;
        input [7:0] x;
        begin
            xtime = {x[6:0], 1'b0} ^ (x[7] ? 8'h1b : 8'h00);
        end
    endfunction

endmodule


/* AES final round for every two clock cycles */
module final_round (clk, state_in, key_in, state_out);
    input              clk;
    input      [127:0] state_in;
    input      [127:0] key_in;
    output reg [127:0] state_out;

    wire [127:0] sb_out;
    wire [127:0] sr_out;
    wire [127:0] ark_out;

    // 1. SubBytes
    S4 s_box_0 (clk, state_in[127:96], sb_out[127:96]);
    S4 s_box_1 (clk, state_in[95:64],  sb_out[95:64]);
    S4 s_box_2 (clk, state_in[63:32],  sb_out[63:32]);
    S4 s_box_3 (clk, state_in[31:0],   sb_out[31:0]);

    // 2. ShiftRows
    assign sr_out[127:96] = {sb_out[127:120], sb_out[87:80],   sb_out[47:40],   sb_out[7:0]};
    assign sr_out[95:64]  = {sb_out[95:88],   sb_out[55:48],   sb_out[15:8],    sb_out[103:96]};
    assign sr_out[63:32]  = {sb_out[63:56],   sb_out[23:16],   sb_out[111:104], sb_out[71:64]};
    assign sr_out[31:0]   = {sb_out[31:24],   sb_out[119:112], sb_out[79:72],   sb_out[39:32]};

    // 3. AddRoundKey
    assign ark_out = sr_out ^ key_in;

    always @ (posedge clk) begin
        state_out <= ark_out;
    end

endmodule