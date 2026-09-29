`default_nettype none

// Read-only helper checker, bound to `top`. Adds no assumptions and does not
// constrain the design; it only asserts a structural fact about the RTL.
//
// top computes x' = x ^ u ^ rotl(u,1) on every non-reset cycle. XOR-ing any
// value with its own left-rotation-by-1 is a cyclic telescoping sum in which
// every bit of u appears exactly twice, so the result always has even parity
// (XOR-reduction 0), for any u whatsoever -- independent of x. Reset sets
// x = 1 (odd parity). Parity is therefore a conserved (input-independent)
// invariant of x, and odd parity trivially implies x != 0.
module top_parity_checker #(
    parameter int W = 16
) (
    input  wire         clk,
    input  wire [W-1:0] x
);

    ap_parity_odd:
        assert property (@(posedge clk) ^x == 1'b1);

endmodule

bind top top_parity_checker #(.W(W)) u_parity_checker (.clk(clk), .x(x));

`default_nettype wire
