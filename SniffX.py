import frida
import sys

def get_pid(target_app):
    device = frida.get_usb_device()
    processes = device.enumerate_processes()
    
    for process in processes:
        if target_app.lower() in process.name.lower():
            print(f"[+] Found {target_app}: PID {process.pid}")
            return process.pid
    
    print(f"[-] Process {target_app} not found.")
    sys.exit(1)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <app_name or PID>")
    sys.exit(1)

target = sys.argv[1]

try:
    if target.isdigit(): 
        pid = int(target)
    else:  
        pid = get_pid(target)
    
    device = frida.get_usb_device()
    session = device.attach(pid)
    print(f"[+] Attached to PID {pid}")

except Exception as e:
    print(f"[-] Error attaching to process: {e}")
    sys.exit(1)

script_code = """
var functions_to_hook = [
    'NSURLSession', 
    'NSURLConnection',
    'CFNetwork',
    'send',
    'SSL_write',
    'SSL_read'
];

var logFile = "/tmp/sniffed_data.log";

function logData(data) {
    var file = new File(logFile, "a");
    file.write(data + "\\n");
    file.flush();
    file.close();
}

functions_to_hook.forEach(function(func) {
    try {
        var addr = Module.findExportByName(null, func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    console.log("\\n[+] Intercepted " + func);
                    if (func == 'SSL_write') {
                        var data = Memory.readByteArray(args[1], args[2].toInt32());
                        console.log("Encrypted Data Sent:", data);
                        logData("[SSL_write] " + hexdump(data));
                    } else if (func == 'SSL_read') {
                        var data = Memory.readByteArray(args[1], args[2].toInt32());
                        console.log("Encrypted Data Received:", data);
                        logData("[SSL_read] " + hexdump(data));
                    } else if (func == 'send') {
                        var data = Memory.readByteArray(args[1], args[2].toInt32());
                        console.log("Raw Data Sent:", data);
                        logData("[send] " + hexdump(data));
                    } else {
                        console.log("Request Intercepted in " + func);
                    }
                }
            });
            console.log("[+] Hooked " + func);
        }
    } catch (err) {
        console.log("[-] Error hooking " + func + ": " + err);
    }
});



var classNSURLSession = ObjC.classes.NSURLSession;
if (classNSURLSession) {
    console.log("[+] Hooking NSURLSession");

    Interceptor.attach(classNSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
        onEnter: function(args) {
            console.log("\\n[+] Intercepted NSURLSession dataTaskWithRequest");
            var request = new ObjC.Object(args[2]);
            var url = request.URL().absoluteString().toString();
            var method = request.HTTPMethod().toString();
            var headers = request.allHTTPHeaderFields();
            var body = request.HTTPBody();

            console.log("URL: " + url);
            console.log("Method: " + method);
            console.log("Headers: " + headers.toString());

            if (body) {
                console.log("Body: " + body.bytes().toString());
                logData("[NSURLSession] URL: " + url + " | Method: " + method + " | Body: " + body.bytes().toString());
            }
        }
    });
}

try {
    Interceptor.attach(Module.findExportByName(null, 'SecTrustEvaluate'), {
        onEnter: function(args) {
            console.log("[+] Bypassing SSL Pinning...");
        },
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    console.log("[+] SSL Pinning Disabled");
} catch (err) {
    console.log("[-] Error disabling SSL Pinning: " + err);
}
"""

try:
    script = session.create_script(script_code)
    script.load()
    print("[+] Script loaded successfully and waiting for calls...")
    sys.stdin.read() 
except Exception as e:
    print(f"[-] Error loading script: {e}")

