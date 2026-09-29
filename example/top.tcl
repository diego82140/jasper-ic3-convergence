clear -all
analyze -sv12 top.sv
elaborate
clock clk
reset -expression ~rstn

