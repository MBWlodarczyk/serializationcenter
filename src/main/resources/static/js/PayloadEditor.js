function btn1_handler() {
    var payload = document.getElementById("formInput6").value
    var xhr = new XMLHttpRequest();
    xhr.open("POST", '../payloadeditor.html', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        payload: payload
    }));
}

window.onload = function () {
    var desString = document.getElementById("deserString")
    var download = document.getElementById("download")
    if (desString.innerHTML.startsWith("\nSTREAM_MAGIC")) {
        download.style.visibility = "visible"
    }
}
