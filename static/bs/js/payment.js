console.log("Sanity check!");
// var order_id = JSON.parse($("#mydiv").data("order_id"));
//var order_id = JSON.parse(document.getElementById("mydiv").dataset.order_id);
var myVariable = {{ order.id | tojson }};
var order_id = {{ order.id | tojson }};
console.log(order_id);

// Get Stripe publishable key
fetch("/config")
.then((result) => { return result.json(); })
.then((data) => {
  // Initialize Stripe.js
  const stripe = Stripe(data.publicKey);

  // Event handler
  document.querySelector("#submitBtn").addEventListener("click", () => {
    // Get Checkout Session ID
    fetch("/create-checkout-session")
    .then((result) => { return result.json(); })
    .then((data) => {
      console.log(data);
      // Redirect to Stripe Checkout
      return stripe.redirectToCheckout({sessionId: data.sessionId})
    })
    .then((res) => {
      console.log(res);
    });
  });
});