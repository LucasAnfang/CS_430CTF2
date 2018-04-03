module.exports = (password) => {
    var result = { 
        message: null,
        valid: true
    }
    if(password == "") {
        result.message = ("Error: Password cannot be blank!");
        result.valid = false;
    } 
    else {
        re = /^\w+$/;
        if(!re.test(password)) {
            result.message = ("Error: Password must contain only letters, numbers and underscores!");
            result.valid = false;
        }
        if(password.length < 6) {
            result.message = ("Error: Password must contain at least six characters!");
            result.valid = false;
        }
        re = /[0-9]/;
        if(!re.test(password)) {
            result.message = ("Error: password must contain at least one number (0-9)!");
            result.valid = false;
        }
        re = /[a-z]/;
        if(!re.test(password)) {
            result.message = ("Error: password must contain at least one lowercase letter (a-z)!");
            result.valid = false;
        }
        re = /[A-Z]/;
        if(!re.test(password)) {
            result.message = ("Error: password must contain at least one uppercase letter (A-Z)!");
            result.valid = false;
        }
    } 
    return result;
}