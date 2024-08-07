import os

# chkrootkit/chkproc.c
MAX_PROCESSES = 4194384     

def find_hidden_procs(ps_out=None):
    if not ps_out:
        ps_out = os.popen("ps mauxw | awk '{print $2}' | grep -v - | grep -v PID").read().strip().split("\n")
    
    print(f"ps count: {len(ps_out)}")
    proc_out = {}

    # brute force, because we cannot trust getdents syscall
    for i in range(0, MAX_PROCESSES+1):
        try:
            with open(f"/proc/{i}/status") as sd:
                status = sd.readlines()
            
            # if tgid is not same as pid, it's a thread
            for line in status:
                if line.startswith("Tgid"):
                    tgid = line.split("\t")[1].strip("\n")
            if int(tgid) != i:
                continue
            
            # collect cmdline for display
            with open(f"/proc/{i}/cmdline") as fd:
                proc_out[str(i)] = fd.readline()
        except FileNotFoundError:
            continue

    print(f"proc brute-force count: {len(proc_out)}")
    
    print("Hidden procs")
    for pid, cmd in proc_out.items():
        if pid not in ps_out:
            print(f" - {pid}\t{cmd}")
    print("---\n")


def test_hidden_proc():
    # exclude self pid from ps output
    pid = os.getpid()
    ps_out = os.popen("ps mauxw | awk '{print $2}' | grep -v - | grep -v PID | grep -v " + f"{pid}").read().strip().split("\n")
    find_hidden_procs(ps_out)



if __name__ == "__main__":
    find_hidden_procs()
    print("TEST OUTPUT")
    test_hidden_proc()
