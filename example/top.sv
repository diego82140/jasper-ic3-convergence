`default_nettype none

module top #(
    parameter int W = 16  // Requires W >= 2.
) (
    input  wire         clk,
    input  wire         rstn,
    input  wire [W-1:0]  u,
    output wire         q
);

    logic [W-1:0] x;

    wire [W-1:0] rotated_u;
    assign rotated_u = {u[W-2:0], u[W-1]};

    always_ff @(posedge clk) begin
        if (!rstn)
            x <= {{(W-1){1'b0}}, 1'b1};
        else
            x <= x ^ u ^ rotated_u;
    end

    assign q = (x != '0);

    // The safety target. No helper is included.
    ap_never_zero:
        assert property (@(posedge clk)
            x != '0);

endmodule

`default_nettype wire

