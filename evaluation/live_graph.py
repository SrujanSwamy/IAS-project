import matplotlib
try:
    import tkinter  # Check if tkinter is available
    matplotlib.use('TkAgg')
except ImportError:
    matplotlib.use('WebAgg')  # Fallback: opens live graph in browser
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import csv
import os

# Set up the figure and two subplots
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))

metrics_file = 'evaluation/metrics.csv'

def animate(i):
    if not os.path.exists(metrics_file):
        return

    times, rates, entropies = [], [], []
    
    try:
        with open(metrics_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                times.append(float(row['Timestamp']))
                rates.append(float(row['FlowRate']))
                entropies.append(float(row['Entropy']))
    except Exception:
        return # Ignore read errors if file is being written to

    if not times:
        return

    # Normalize time so the graph starts at 0 seconds
    start_time = times[0]
    rel_times = [(t - start_time) for t in times]

    # Keep only the last 20 data points (rolling window) so it doesn't get squished
    window = 20
    rel_times = rel_times[-window:]
    rates = rates[-window:]
    entropies = entropies[-window:]

    # Draw Flow Rate Subplot
    ax1.clear()
    ax1.plot(rel_times, rates, label='Flow Rate (pkts/sec)', color='crimson', marker='o')
    ax1.set_ylabel('Packet Rate')
    ax1.set_title('Live Network Telemetry')
    ax1.axhline(y=500, color='black', linestyle='--', label='Spike Threshold (500)')
    ax1.legend(loc='upper left')
    ax1.grid(True, alpha=0.3)

    # Draw Entropy Subplot
    ax2.clear()
    ax2.plot(rel_times, entropies, label='Normalized Entropy', color='dodgerblue', marker='o')
    ax2.set_xlabel('Time (seconds)')
    ax2.set_ylabel('Entropy (Randomness)')
    ax2.set_ylim(-0.1, 1.1)
    ax2.axhline(y=0.5, color='orange', linestyle='--', label='Drop Threshold (0.5)')
    ax2.legend(loc='upper left')
    ax2.grid(True, alpha=0.3)

# Run the animation loop every 1000ms (1 second)
ani = animation.FuncAnimation(fig, animate, interval=1000, cache_frame_data=False)

fig.canvas.manager.set_window_title('SDN Anomaly Detection Live Dashboard')
plt.tight_layout()
plt.show()