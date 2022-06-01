from GetCallsLib import get_all_function_calls
import time

if __name__ == '__main__':
    start_time = time.time()

    dll_file_path = 'kernel32.dll'
    calls = get_all_function_calls(dll_file_path)

    end_time = time.time()
    time_diff = (end_time - start_time)
    print("\n[*] Finding calls for functions in %s" % dll_file_path)
    print("[+] Analized %d functions in %ld ms" % (len(calls), time_diff * 1000))

    function_name = 'local!RtlCopyMemory'

    print("[+] Showing results for %s" % function_name)
    for function_called in calls[function_name]:
        print('\t[-] Call to: %s' % function_called)