clear -all
# Launched in this directory:
#   BUDGET=10m slurm/submit.sh batch <run> <this dir> proof_graph.tcl          (experiment)
#   BUDGET=<=4x basis> BUDGET_CLASS=replay GRAPH_READY=<receipt> ... proof_graph.tcl
# Minimal, linear two-level graph: it stops at the first failure; a real graph
# blocks only the descendants of a failed node and keeps proving independent branches.
analyze -sv12 top.sv
analyze -sv12 parity_checker.sv
elaborate
clock clk
reset -expression ~rstn
# ProofMaster is switched by the environment (PASS_ENV=IC3_COLD): a cold replay
# sets IC3_COLD=1; a warm basis run leaves it unset.
set cold [expr {[info exists ::env(IC3_COLD)] && $::env(IC3_COLD) ne "0"}]
if {$cold} { set_proofmaster off } else { set_proofmaster on }
puts "PROOFMASTER [expr {$cold ? "off" : "on"}]"

# Receipt contract (tools/graph_ready.py reads these lines token by token).
proc sha256_of {path} { return [lindex [exec sha256sum $path] 0] }
puts "GRAPH_INPUTS graph_sha256=[sha256_of [info script]] checker_sha256=[sha256_of [file join [file dirname [info script]] parity_checker.sv]]"
set root   <embedded>::top.u_parity_checker.ap_parity_odd
set target <embedded>::top.ap_never_zero
puts "GRAPH_NODES $root $target"
puts "GRAPH_COVERS"
# This example is launched as an experiment (BUDGET=10m), so it sets the matching
# prove limit. A replay keeps the project's native limit instead.
if {!$cold} { set_prove_time_limit 10m }

set baseline_assumes [assume -list -silent]

proc env_ok {} {
    if {[assume -list -silent] ne $::baseline_assumes} { return 0 }
    foreach p [get_property_list] {
        if {[lindex [get_property_info $p -list {status}] 0] eq "marked_proven"} { return 0 }
    }
    return 1
}

proc accept {node rc} {
    set info [get_property_info $node -list {status validity_status engine time}]
    puts "RESULT $node [lindex $info 0] [lindex $info 1] [lindex $info 2] [lindex $info 3]"
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
