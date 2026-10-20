Exact-worker real-computation regression

This invokes the uploaded b5006df1 worker through its original native socket
protocol. Its real main, real IC3 and real SAT code run without replacement.
The client sends a generated Boolean model and ordinary serialized proof
commands, decodes the real report/verdict transport, and prints received
statistics immediately. This is not a fake solver or callback receiver.

The generated model tests counter and LFSR assertions. model.sv is provenance
for model.bs; the netlist was generated using the available reference frontend.
job-commands.json records the reusable native job commands.

M/M4 here are requested native engine labels/indexes with a minimal common IC3
configuration. These runs do not establish the entire matching frontend's
M/M4 tuned presets. The emitted native verdicts and statistics are real.

Producer replay (optional, never required by customers):
python3 run.py --worker /path/to/exact/Linux64/bin/jg_proof \
  --runtime /path/to/bin_atlas --package /path/to/jipstats-linux-x86_64 \
  --output /path/to/new-results

Requires the three named existing installations/binaries, not Jasper sources.
The runtime supplies dependency libraries; its incompatible frontend is not
used. The worker is never edited, and its SHA-256 is checked before and after.
