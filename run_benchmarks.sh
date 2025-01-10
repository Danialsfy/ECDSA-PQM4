#!/bin/bash

# Check if algorithm is provided as the first argument
if [[ -z "$1" ]]; then
    echo "Error: No algorithm specified."
    echo "Usage: ./run_benchmark.sh <algorithm> [num_runs]"
    exit 1
fi

ALGORITHM="$1"  # The algorithm to benchmark (first argument)
NUM_RUNS=10     # Default number of runs

# Check if user specified the number of runs (second argument)
if [[ ! -z "$2" ]]; then
    NUM_RUNS="$2"  # Use the second argument as the number of runs if provided
fi

# Function to run the benchmark command
run_benchmark() {
    local algorithm=$1
    local iteration=$2
    echo "Running iteration $iteration with algorithm $algorithm"
    python3 benchmarks.py -p stm32f4discovery "$algorithm"
}

# Loop to run the benchmark the specified number of times
for ((i = 1; i <= NUM_RUNS; i++)); do
    run_benchmark "$ALGORITHM" "$i"
done
