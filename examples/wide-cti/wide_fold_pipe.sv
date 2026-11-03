`default_nettype none
// wide_fold_pipe (r5) -- VALIDATION FIXTURE ONLY (not a model of any project DUT).
// PREPARED, NOT LAUNCHED unless r4 (job 2560141) native evidence shows it is too
// costly. Change vs r4: 2 stages instead of 4, and the bug is enabled by a free
// input bug_en instead of an 8-bit data pattern (shorter, easier reachable bug).
// Wide vectors and the parity relation are unchanged.
// Clock clk; synchronous active-low reset rstn (Tcl: clock clk; reset -expression ~rstn).
// No assumptions; all inputs free. Contract (source level, controls/fold_model_r5.py):
//   fold = XOR of all W bits (F = 1); fold(rotl1 d) == fold(d);
//   fold(shl1 d) == fold(d) ^ d[W-1].
// Target ap_fold_s1: v1 |-> fold(d1) == c1. Violated iff the bug fires with d0[W-1]==1.
// Every cube over {v1,c1,d1} wholly inside the violation set constrains all W d1 bits
// (source-level statement only; native cube size remains UNOBSERVED until captured).
module wide_fold_pipe #(
    parameter int W = 6144,
    parameter int F = 1
) (
    input  wire          clk,
    input  wire          rstn,
    input  wire          stall,
    input  wire          bug_en,
    input  wire          in_valid,
    input  wire [W-1:0]  in_data
);
    logic          v0, v1;
    logic [W-1:0]  d0, d1;
    logic          c0, c1;
    wire bug_fire = v0 && bug_en;
    always_ff @(posedge clk) begin
        if (!rstn) begin
            v0 <= 1'b0; v1 <= 1'b0; d0 <= '0; d1 <= '0; c0 <= 1'b0; c1 <= 1'b0;
        end else if (!stall) begin
            v0 <= in_valid; d0 <= in_data;                                         c0 <= ^in_data;
            v1 <= v0;       d1 <= bug_fire ? {d0[W-2:0], 1'b0} : {d0[W-2:0], d0[W-1]}; c1 <= c0;
        end
    end
    ap_fold_s1:
        assert property (@(posedge clk) disable iff (!rstn)
            v1 |-> ((^d1) == c1));
endmodule
`default_nettype wire
