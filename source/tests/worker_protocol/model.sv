module native_jg_smoke (
    input logic clk,
    input logic rst,
    input logic advance
);
    logic [1:0] count;
    logic [6:0] depth;
    logic [3:0] small_lfsr;
    logic [31:0] lfsr;

    always_ff @(posedge clk) begin
        if (rst)
            count <= 2'd0;
        else
            count <= count + 2'd1;

        if (rst)
            depth <= 7'd0;
        else if (advance && depth != 7'd100)
            depth <= depth + 7'd1;

        if (rst)
            lfsr <= 32'h1;
        else
            lfsr <= {lfsr[30:0], lfsr[31] ^ lfsr[21] ^ lfsr[1] ^ lfsr[0]};

        if (rst)
            small_lfsr <= 4'h1;
        else
            small_lfsr <= {small_lfsr[2:0], small_lfsr[3] ^ small_lfsr[0]};
    end

    valid_wrap: assert property (
        @(posedge clk) disable iff (rst)
        count == 2'd3 |=> count == 2'd0
    );

    bad_stuck_at_zero: assert property (
        @(posedge clk) disable iff (rst)
        count == 2'd0
    );

    // The transition is injective and reset starts outside its all-zero
    // fixed point.  This target remains for an actual proof engine after the
    // two simple counter properties are resolved by preprocessing.
    engine_lfsr_nonzero: assert property (
        @(posedge clk) disable iff (rst)
        lfsr != 32'h0
    );

    // The same injective recurrence at four bits gives slower abstraction
    // profiles a compact but still stateful, engine-dispatched proof target.
    engine_small_lfsr_nonzero: assert property (
        @(posedge clk) disable iff (rst)
        small_lfsr != 4'h0
    );

    // A nontrivial, reachable failure for trace-oriented engine modes.  The
    // fifty-cycle distance prevents frontend constant folding or reset
    // preprocessing from satisfying the engine-dispatch test by itself.
    engine_depth_never_fifty: assert property (
        @(posedge clk) disable iff (rst)
        depth != 7'd50
    );
endmodule
