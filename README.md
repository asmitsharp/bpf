Problem 2 link :  https://github.com/asmitsharp/bpf-process

Problem 3 Answer :
1. Highlighted Constructs

make(chan func(), 10): Creates a buffered channel that can hold 10 func() items. It's a thread-safe queue for functions.

for i := 0; i < 4; i++: Spawns 4 goroutines. They all listen to the same channel for work.

for f := range cnp: A loop that runs forever, pulling functions off the channel and running them (f()). It's how each "worker" waits for jobs.

2. Use-Cases
This is a worker pool pattern. You use it to:

Control concurrency (limit to 4 parallel tasks).

Handle high volumes of small tasks (e.g., processing API requests, small calculations).

3. Significance of 4 Iterations
It creates a pool of 4 worker goroutines. This limits the number of functions executing concurrently to 4, preventing the system from being overloaded.

4. Significance of make(chan func(), 10)
The 10 is the channel's buffer size. It lets the main thread send up to 10 functions instantly without waiting for a worker to be ready. It decouples the sending and receiving processes slightly.

5. Why “HERE1” is not getting printed
The main goroutine sends the function and then prints "Hello". As soon as main finishes, the program exits and kills all the worker goroutines before they get a chance to execute the function they received. The code doesn't wait for the workers.
