clear -all
# Launched in this directory (slurm/submit.sh batch <run> <this dir> proof_graph.tcl).
analyze -sv12 top.sv
analyze -sv12 parity_checker.sv
elaborate
clock clk
reset -expression ~rstn

# Cold-start replay: prerequisites before consumers. Each node is accepted only
# with status and validity_status both "proven" under the unchanged
# environment; a consumer is attempted only after its prerequisites pass.
# No time limits: a limit could only cut a proof that converges.
set root   <embedded>::top.u_parity_checker.ap_parity_odd
set target <embedded>::top.ap_never_zero
set baseline_assumes [assume -list -silent]

proc env_ok {} {
    if {[assume -list -silent] ne $::baseline_assumes} { return 0 }
    foreach p [get_property_list] {
        if {[lindex [get_property_info $p -list {status}] 0] eq "marked_proven"} { return 0 }
    }
    return 1
}

proc accept {node rc} {
    set info [get_property_info $node -list {status validity_status engine trace_length}]
    puts "RECEIPT $node rc=$rc info={$info} env_ok=[env_ok]"
    if {$rc eq "overconstrained" || [lindex $info 0] ne "proven"
            || [lindex $info 1] ne "proven" || ![env_ok]} {
        puts "STOP: $node not accepted."
        exit 1
    }
}

accept $root [prove -property $root]
if {![env_ok]} { puts "STOP: environment changed before reuse."; exit 1 }
accept $target [prove -property $target -with_proven]

puts "ALL ACCEPTED: $root, $target"
exit 0
