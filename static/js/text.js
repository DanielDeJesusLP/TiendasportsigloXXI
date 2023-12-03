
function filtrarCaracteres() {
    var textarea = document.getElementById('mensaje');
    var texto = textarea.value;

    // Filtrar caracteres que no sean letras ni números
    texto = texto.replace(/[^a-zA-Z0-9]/g, '');

    // Actualizar el valor del textarea con el texto filtrado
    textarea.value = texto;
}