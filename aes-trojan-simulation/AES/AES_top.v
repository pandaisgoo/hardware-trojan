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

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            out <= {128{1'bx}};  
        end 
        else begin
            out <= ciphertext;  
        end
    end

endmodule