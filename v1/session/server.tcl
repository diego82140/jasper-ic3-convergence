# Persistent Jasper session: evaluates request files at global scope, in
# order, until a request calls `session_stop`. Started on a Slurm node by
#   slurm/submit.sh session <run_dir> <launch_dir>
# which runs JG_SESSION_DIR=<run_dir>/io <jipstats> <jasper> -batch
# -proj <run_dir>/jgproject -tcl session/server.tcl. Send requests with
# session/send.sh <run_dir>/io. State (elaboration, added asserts, proof
# results) persists across requests.

if {[info exists ::env(JG_SESSION_DIR)]} {
    set ::session_io $::env(JG_SESSION_DIR)
} else {
    set ::session_io [file join [pwd] jg_session_io]
}
file mkdir $::session_io
set ::session_running 1
proc session_stop {} { set ::session_running 0 }

puts "JG_SESSION READY $::session_io"
flush stdout

while {$::session_running} {
    set reqs [lsort [glob -nocomplain -directory $::session_io *.req]]
    if {[llength $reqs] == 0} {
        after 200
        continue
    }
    foreach req $reqs {
        set id [file rootname [file tail $req]]
        puts "JG_SESSION BEGIN $id"
        flush stdout
        # catch keeps a failing command from ending the batch session.
        set rc [catch {uplevel #0 [list source $req]} result]
        puts "JG_SESSION END $id rc=$rc"
        flush stdout
        set fh [open [file join $::session_io $id.tmp] w]
        puts $fh "rc=$rc"
        puts $fh $result
        close $fh
        file rename -force [file join $::session_io $id.tmp] [file join $::session_io $id.resp]
        file delete $req
        if {!$::session_running} break
    }
}

puts "JG_SESSION STOPPED"
flush stdout
exit
