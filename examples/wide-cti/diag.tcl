# diag.tcl -- LABELED FINITE VALIDATION DIAGNOSTIC for the wide_fold_pipe fixture.
# Not a convergence/non-inductiveness experiment and not a project proof.
# One engine per job (FIX_ENGINE = M or M4). Command shape mirrors the jipstats
# native qualification Tcl (set_prove_orchestration off; prove -property
# -engine_mode -verbosity 20 -time_limit; get_property_info -list; exit -force).
# Commands beyond that receipt (assume -list -silent, get_property_list,
# visualize -violation / -get_value) are each wrapped in catch and logged; their
# availability on each release is a PENDING native obligation (see HANDOFF.json).
# No Tcl wall clock is used; prove time comes from get_property_info {time}.
# Inputs: FIX_DIR (frozen fixture dir), FIX_OUT (fresh output dir), FIX_ENGINE, FIX_LABEL.
set fix_dir $::env(FIX_DIR)
set out_dir $::env(FIX_OUT)
set eng     $::env(FIX_ENGINE)
set label   $::env(FIX_LABEL)
if {$eng ne "M" && $eng ne "M4"} { puts "FIXTURE_ERROR engine=$eng"; exit -force 2 }
file mkdir $out_dir
set rf [open [file join $out_dir receipts.txt] a]
proc rcpt {msg} { global rf; puts $rf $msg; flush $rf; puts "FIXTURE_RECEIPT $msg" }

clear -all
analyze -sv12 [file join $fix_dir wide_fold_pipe.sv]
elaborate -top wide_fold_pipe
clock clk
reset -expression ~rstn
rcpt "SETUP label=$label engine=$eng"

# Environment and inventory audit (read-only).
if {[catch {assume -list -silent} assumes]} { rcpt "ASSUMPTIONS query_failed={$assumes}" } else {
    rcpt "ASSUMPTIONS count=[llength $assumes] list={$assumes}" }
if {[catch {get_property_list} plist]} { rcpt "INVENTORY query_failed={$plist}"; set plist {} }
foreach p $plist {
    if {[catch {get_property_info $p -list {type disabled liveness status}} pi]} { set pi "?($pi)" }
    rcpt "PROPERTY name=$p info={$pi}"
}
set props [get_property_list -include [list name *.ap_fold_s1]]
if {[llength $props] != 1} { rcpt "FIXTURE_ERROR cannot resolve ap_fold_s1: {$props}"; close $rf; exit -force 2 }
set prop [lindex $props 0]

set_prove_orchestration off
rcpt "PROVE_BEGIN property=$prop engine_mode=$eng time_limit=600s"
set rc [prove -property $prop -engine_mode $eng -verbosity 20 -time_limit 600s]
set info [get_property_info $prop -list {status validity_status engine trace_length min_length time}]
rcpt "RESULT property=$prop rc=$rc info={$info}"

# Trace retrieval (r5b). Syntax from the original release's Command Reference
# (apidoc/original-command-reference.txt, visualize section): -violation returns
# cex|ar_cex|proven|undetermined|error; -get_value cycles start at 1 ("1:$");
# -get_length/-get_value take -window; -save -vcd; -confirm -vcd. A trace is
# recorded as TRACE_VALID=1 only if visualize returned exactly "cex" AND every
# length/value/save/confirm call returned without error. Any error -> TRACE_VALID=0;
# a created file with errors is NOT a witness. Native cycle numbering is kept as
# reported; it is not mapped to the offline model's update count.
if {[lindex $info 0] eq "cex"} {
    set ok 1
    set w wfp_cex
    set tf [open [file join $out_dir cex_trace.txt] w]
    puts $tf "CEX property=$prop provenance={$info}"
    if {[catch {visualize -violation -property $prop -new_window $w -batch -silent -proof_time 120s} vrc]} {
        puts $tf "ERROR visualize_violation {$vrc}"; set ok 0; set vrc error
    }
    puts $tf "VISUALIZE_RETURN $vrc"
    if {$vrc ne "cex"} { set ok 0 }
    set vlen ""
    if {$ok && [catch {visualize -get_length -window $w} vlen]} { puts $tf "ERROR get_length {$vlen}"; set ok 0 }
    puts $tf "LENGTH $vlen"
    if {$ok} {
        foreach {s rad} {rstn 2 stall 2 bug_en 2 in_valid 2 v0 2 v1 2 bug_fire 2 c0 2 c1 2 in_data 16 d0 16 d1 16} {
            if {[catch {visualize -get_value $s {1:$} -radix $rad -window $w} v]} {
                puts $tf "ERROR get_value $s {$v}"; set ok 0
            } else {
                puts $tf "VALUE $s radix=$rad {$v}"
            }
        }
    }
    set vcd [file join $out_dir cex.vcd]
    if {$ok && [catch {visualize -save -vcd $vcd -force} sv]} { puts $tf "ERROR save_vcd {$sv}"; set ok 0 }
    if {$ok && [catch {visualize -confirm -vcd $vcd -new_window ${w}_confirm -batch} cf]} { puts $tf "ERROR confirm {$cf}"; set ok 0 } elseif {$ok} { puts $tf "CONFIRM_RETURN {$cf}" }
    puts $tf "TRACE_VALID $ok"
    close $tf
    rcpt "CEX_TRACE visualize=$vrc length=$vlen trace_valid=$ok file=cex_trace.txt"
}
rcpt "DONE label=$label"
close $rf
exit -force 0
