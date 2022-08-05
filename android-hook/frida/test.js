// test1
// setTimeout(function (){
//     Java.perform(function (){
//       console.log("\n[*] enumerating classes...");
//       var sum = 0;
//       Java.enumerateLoadedClasses({
//         onMatch: function(_className){
//           console.log("[*] found instance of '"+_className+"'");
//           sum += 1;
//         },
//         onComplete: function(){
//           console.log("[*] class enuemration complete");
//           console.log("[*] the number of the classes:" + sum);
//         }
//       });
//     });
//   });

//test2
// setTimeout(function (){
//     Java.perform(function (){
        // step-1
        // Java.enumerateLoadedClasses({
        //     onMatch: function(instance){
        //       if (instance.split(".")[1] == "bluetooth"){
        //         console.log("[->]\t"+instance);
        //       }
        //     },
        //     onComplete: function() {
        //       console.log("[*] class enuemration complete");
        //     }
        // });
        // step-2
        // Java.choose("android.bluetooth.BluetoothDevice",{
        //     onMatch: function (instance){
        //       console.log("[*] "+" android.bluetooth.BluetoothDevice instance found"+" :=> '"+instance+"'");
        //       console.log(instance.getAddress())
        //       console.log(instance.getName())
        //     },
        //     onComplete: function() { console.log("[*] -----");}
        // });
//     });
// });

// test3
function enumMethods(targetClass)
{
	var hook = Java.use(targetClass);
	var ownMethods = hook.class.getDeclaredMethods();
	hook.$dispose;
	return ownMethods;
}

setTimeout(function (){
    Java.perform(function (){
        var a = enumMethods("android.bluetooth.BluetoothDevice")
		a.forEach(function(s) {
			console.log(s);
		});
    });
});