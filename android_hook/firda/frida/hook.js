setTimeout(function (){
    Java.perform(function (){
        var hook = Java.use("com.example.testfrida2.MainActivity");
        var targetMethod = 'fun';
        var overloadCount = hook[targetMethod].overloads.length;
        console.log("Tracing " + targetMethod + " [" + overloadCount + " overload(s)]");
        for (var i = 0; i < overloadCount; i++) {
            hook[targetMethod].overloads[i].implementation = function() {
                console.warn("\n*** entered " + targetMethod);
                var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                console.log("\nBacktrace:\n" + bt); 
        
                if (arguments.length) console.log();
                for (var j = 0; j < arguments.length; j++) {
                    console.log("arg[" + j + "]: " + arguments[j]);
                }

                var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
                console.log("\nretval: " + retval);
                console.warn("\n*** exiting " + targetMethod);
                return retval;
            }
        }
    });
});