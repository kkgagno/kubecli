def cleanup_old_files(directory, days_to_keep):
    """Deletes files in a directory older than a specified number of days."""
    if not os.path.exists(directory):
        return

    now = datetime.datetime.now()
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        try:
            # Extract timestamp from filename
            timestamp_str = filename.split('_')[0]
            file_time = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d')
            if (now - file_time).days > days_to_keep:
                os.remove(file_path)
        except (ValueError, IndexError):
            # Handle files that don't match the expected naming convention
            continue
