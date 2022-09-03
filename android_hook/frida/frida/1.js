function main() {
    Java.perform(() => {
        var my_class = Java.use("com.example.testfrida2.MainActivity");
        my_class.fun.implementation = function(x,y){
                this.fun(2,5);
                console.log("x => " + x + "   y => " + y);
            };
    });
}

setImmediate(main)