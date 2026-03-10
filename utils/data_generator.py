#!/usr/bin/env python3
"""
Sensor Data Generator Script

Generates randomized environmental sensor data for the past 24 hours.
Temperature range: 65-80°F (realistic ICS server room environment)
Humidity range: 30-60%
Readings every 15 minutes (96 data points)

Usage:
    python utils/data_generator.py
    python utils/data_generator.py --hours 48  # Generate 48 hours of data
"""

import json
import os
import random
import uuid
import argparse
from datetime import datetime, timedelta

# Default configuration
DEFAULT_HOURS = 24
READING_INTERVAL_MINUTES = 15
TEMP_MIN = 65.0
TEMP_MAX = 80.0
HUMIDITY_MIN = 30.0
HUMIDITY_MAX = 60.0
SENSOR_ID = "SENSOR-001"


def generate_reading(timestamp: datetime, prev_temp: float = None,
                     prev_humidity: float = None) -> dict:
    """
    Generate a single sensor reading.

    Uses previous values to create more realistic gradual changes
    rather than completely random jumps.
    """
    # Generate temperature with gradual variation
    if prev_temp is not None:
        # Vary by up to 1.5 degrees from previous reading
        temp_change = random.uniform(-1.5, 1.5)
        temperature = prev_temp + temp_change
        # Keep within bounds
        temperature = max(TEMP_MIN, min(TEMP_MAX, temperature))
    else:
        temperature = random.uniform(TEMP_MIN, TEMP_MAX)

    # Generate humidity with gradual variation
    if prev_humidity is not None:
        # Vary by up to 3% from previous reading
        humidity_change = random.uniform(-3.0, 3.0)
        humidity = prev_humidity + humidity_change
        # Keep within bounds
        humidity = max(HUMIDITY_MIN, min(HUMIDITY_MAX, humidity))
    else:
        humidity = random.uniform(HUMIDITY_MIN, HUMIDITY_MAX)

    return {
        'id': str(uuid.uuid4()),
        'timestamp': timestamp.isoformat(),
        'temperature_f': round(temperature, 2),
        'humidity_percent': round(humidity, 2),
        'sensor_id': SENSOR_ID
    }


def generate_sensor_data(hours: int = DEFAULT_HOURS) -> list:
    """
    Generate sensor readings for the specified number of hours.

    Returns a list of readings from oldest to newest.
    """
    readings = []
    num_readings = (hours * 60) // READING_INTERVAL_MINUTES

    # Start from hours ago
    current_time = datetime.utcnow() - timedelta(hours=hours)

    prev_temp = None
    prev_humidity = None

    for _ in range(num_readings):
        reading = generate_reading(current_time, prev_temp, prev_humidity)
        readings.append(reading)

        # Update for next iteration
        prev_temp = reading['temperature_f']
        prev_humidity = reading['humidity_percent']
        current_time += timedelta(minutes=READING_INTERVAL_MINUTES)

    return readings


def save_sensor_data(readings: list, filepath: str):
    """Save sensor readings to JSON file."""
    data = {'readings': readings}
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Saved {len(readings)} readings to {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate simulated environmental sensor data'
    )
    parser.add_argument(
        '--hours',
        type=int,
        default=DEFAULT_HOURS,
        help=f'Number of hours of data to generate (default: {DEFAULT_HOURS})'
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output file path (default: data/sensor_data.json)'
    )

    args = parser.parse_args()

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        # Default to data directory relative to project root
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        output_path = os.path.join(project_root, 'data', 'sensor_data.json')

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Generate and save data
    print(f"Generating {args.hours} hours of sensor data...")
    readings = generate_sensor_data(args.hours)
    save_sensor_data(readings, output_path)

    # Print summary
    if readings:
        temps = [r['temperature_f'] for r in readings]
        humids = [r['humidity_percent'] for r in readings]
        print(f"\nSummary:")
        print(f"  Time range: {readings[0]['timestamp']} to {readings[-1]['timestamp']}")
        print(f"  Temperature: {min(temps):.1f}°F - {max(temps):.1f}°F (avg: {sum(temps)/len(temps):.1f}°F)")
        print(f"  Humidity: {min(humids):.1f}% - {max(humids):.1f}% (avg: {sum(humids)/len(humids):.1f}%)")


if __name__ == '__main__':
    main()
