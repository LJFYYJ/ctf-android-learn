console.log("Script loaded successfully ");

function callSecretFun() { 
    Java.perform(function () {
        Java.choose("com.example.testfrida2.MainActivity", {
            onMatch: function (instance) {
                console.log("Found instance: " + instance);
                console.log("Result of secret func: " + instance.secret());
            },
            onComplete: function () { }
        });
    });
}
rpc.exports = {
    callsecretfunction: callSecretFun
};