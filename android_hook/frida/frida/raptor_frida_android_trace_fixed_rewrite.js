function trace(pattern) {
    // 如果pattern中不存在!就是java，存在就是module
    var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";
    if(type === "module") {
        console.log("module");
        // 获取所有匹配的且不重复的module
        var res = new ApiResolver("module");
        var matches = res.enumerateMatchesSync(pattern);
        var targets = uniqBy(matches, JSON.stringify);
        // 遍历每一个module
        targets.forEach(function(target) {
            try {
                traceModule(target.address, target.name);
            }
            catch(error) {}
        });
    } else if (type === "java") {
        console.log("java");
        // trace Java clas
        var found = true;
        Java.enumerateLoadedClasses({
            onMatch: function(aClass) {
                // 判断每个类是否满足给定的模式要求
                if(aClass.match(pattern)) {
                    found = true;
                    console.log("found is true");
                    var className = aClass.match(/[L]?(.*);?/)[1].replace(/\//g, ".");
                    traceClass(className);
                }
            },
            onComplete: function() {}
        });
    }
    // trace Java Method
    if(!found) {
        try {
            traceMethod(pattern);
        } catch(err) {}
    }
}


function traceClass(targetClass) {
    console.log("entering traceClass");
    // 获取目标类的所有方法
    var hook = Java.use(targetClass);
    var methods = hook.class.getDeclaredMethods();
    hook.$dispose();
    // 解析获取方法名
    var parsedMethods = [];
    methods.forEach(function(method) {
        try{
            parsedMethods.push(method.toString().replace(targetClass+".", "TOKEN")
                .match(/\sTOKEN(.*)\(/)[1]);
        } catch (err) {}
    });
    console.log("entering traceMethods");
    // 去除重复方法名
    var targets = uniqBy(parsedMethods, JSON.stringify);
    // 解析每一个方法
    targets.forEach(function(targetMethod) {
        try{
            traceMethod(targetClass + "." + targetMethod);
        } catch(err) {}
    });
}


function traceMethod(targetClassMethod) {
    var delim = targetClassMethod.lastIndexOf(".");
    if(delim == -1) return;
    // 获取单独类名和单独方法名
    var targetClass = targetClassMethod.slice(0, delim);
    var targetMethod = targetClassMethod.slice(delim+1, targetClassMethod.length);
    // 获取目标类中所有的同名方法数量
    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;
    console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");
    // 处理每个重载的方法
    for(var i = 0; i < overloadCount; i++) {
        hook[targetMethod].overloads[i].implementation = function() {
            console.warn("\n*** entered " + targetClassMethod);
            // 打印参数
            for(var j = 0; j < arguments.length; j++) {
                console.log("arg[" + j + "]: " + arguments[j]);
            }
            // 打印返回值
            var retval = this[targetMethod].apply(this, arguments);
            console.log("\nretval: " + retval);
			console.warn("\n*** exiting " + targetClassMethod);
            return retval;
        }
    }
}


function traceModule(impl, name) {
    console.log("Tracing " + impl + " " + name);
    Interceptor.attach(impl, {
        // 进入函数
        onEnter: function(args) {
            console.warn("\n*** entered " + name);
            // Thread.backtrace返回当前线程的调用栈，返回一组Native指针对象
			// DebugSymbol.fromAddress查找地址中的debug信息
            console.log("\nBacktrace\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n"));
        },
        // 离开函数
        onLeave: function(retval) {
            // 打印返回值
            console.log("\nretval " + retval);
            console.warn("\n*** exiting " + name);
        }
    });
}


function uniqBy(array, key) {
    var seen = {};
    // filter()方法创建一个新的数组，新数组中是原数组中符合条件的元素
    return array.filter(function(item) {
        // 将Java对象或值转换为JSON字符串
        var k = key(item);
        // 已经存在该属性，则返回false；否则，返回true同时将k作为seen的新属性
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}


setTimeout(()=> {
    Java.perform(()=> {
        console.log("first entering selector");
        trace("com.whatsapp.protocol");
        // trace("exports:*!open*");
        // trace("exports:*!write*");
		// trace("exports:*!malloc*");
		// trace("exports:*!free*");
    });
});