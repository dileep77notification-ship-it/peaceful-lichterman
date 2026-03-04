const {
  assertFails,
  assertSucceeds,
  initializeTestEnvironment,
} = require("@firebase/rules-unit-testing");
const { before, after, describe, it } = require("mocha");
const fs = require("fs");
const path = require("path");
// Note: This Timestamp refers to the Firestore client SDK Timestamp.
// For rules unit testing, its behavior is generally compatible with rules' server-side timestamps.
const { Timestamp } = require("firebase/firestore");

// Use the project ID from your context
const PROJECT_ID = "vanatvam-booking-dce9d"; // Corrected project ID

let testEnv;
let adminDb, aliceDb, bobDb, unauthDb; // Firestore instances

// --- Test Setup ---
before(async () => {
  const rulesAbsolutePath = path.resolve(__dirname, '../firestore.rules');
  console.log(`[TEST SETUP] Attempting to load rules from path: ${rulesAbsolutePath}`);

  let rulesContent;
  try {
    rulesContent = fs.readFileSync(rulesAbsolutePath, 'utf8');
    console.log('[TEST SETUP] Content of firestore.rules (first 100 chars):');
    console.log('---START OF RULES CONTENT---');
    console.log(rulesContent.substring(0, 100));
    console.log('---END OF RULES CONTENT---');
  } catch (e) {
    console.error(`[TEST SETUP ERROR] Could not read rules file at ${rulesAbsolutePath}:`, e);
    throw e;
  }

  try {
    testEnv = await initializeTestEnvironment({
      projectId: PROJECT_ID,
      firestore: {
        rules: rulesContent,
        host: "127.0.0.1",
        port: 8080,
      },
    });
    console.log('--- DEBUG: initializeTestEnvironment() COMPLETED ---');
  } catch (e) {
    console.error(`\n\n[CRITICAL TEST SETUP ERROR] Failed to initialize Firebase Test Environment:`);
    console.error(`  - Is the Firebase Emulator Suite running?`);
    console.error(`    Run 'firebase emulators:start' in a separate terminal from your project root.`);
    console.error(`  - Is the Firestore emulator listening on 127.0.0.1:8080?`);
    console.error(`  - Original error:`, e);
    throw e;
  }

  if (!testEnv) {
      console.error("[CRITICAL TEST SETUP ERROR] testEnv is unexpectedly undefined after initialization.");
      throw new Error("Test environment not initialized properly.");
  }

  // Create authenticated contexts for different users and an unauthenticated context
  adminDb = testEnv.authenticatedContext("adminId", { isAdmin: true }).firestore();
  aliceDb = testEnv.authenticatedContext("aliceId", { isAdmin: false }).firestore(); // explicitly set isAdmin for Alice
  bobDb = testEnv.authenticatedContext("bobId", { isAdmin: false }).firestore();   // explicitly set isAdmin for Bob
  unauthDb = testEnv.unauthenticatedContext().firestore();

  // Seed initial data with security rules disabled for setup
  await testEnv.withSecurityRulesDisabled(async (context) => {
    const db = context.firestore();
    // Pre-populate users
    await db.collection("users").doc("adminId").set({
      name: "Admin User",
      email: "admin@example.com",
      phone: "111-222-3333",
      profilePicture: "https://example.com/admin.jpg",
      isAdmin: true, // Should match custom claim
      createdAt: Timestamp.now(),
    });
    await db.collection("users").doc("aliceId").set({
      name: "Alice Wonderland",
      email: "alice@example.com",
      phone: "123-456-7890",
      profilePicture: "https://example.com/alice.jpg",
      isAdmin: false, // Should match custom claim
      createdAt: Timestamp.now(),
    });
    await db.collection("users").doc("bobId").set({
      name: "Bob Builder",
      email: "bob@example.com",
      phone: "987-654-3210",
      profilePicture: "https://example.com/bob.jpg",
      isAdmin: false, // Should match custom claim
      createdAt: Timestamp.now(),
    });
    // Pre-populate properties and cottages
    await db.collection("properties").doc("property1").set({
      name: "Luxury Villa",
      location: "Bali",
      ownerId: "adminId", // Assuming admin owns properties for simplicity in tests
      createdAt: Timestamp.now(),
    });
    await db.collection("properties").doc("property1").collection("cottages").doc("cottageA").set({
      name: "Ocean View Cottage",
      beds: 2,
      pricePerNight: 200,
      createdAt: Timestamp.now(),
    });
  });

  console.log('[TEST SETUP] Initial data seeded.');
});

after(async () => {
  await testEnv.cleanup();
  console.log('[TEST TEARDOWN] Test environment cleaned up.');
});

describe("Firestore Security Rules - General Access & Initialization", () => {
  it("should deny any read/write access to unauthenticated users by default", async () => {
    await assertFails(unauthDb.collection("users").doc("aliceId").get());
    await assertFails(unauthDb.collection("users").doc("newId").set({ name: "Unauthorized" }));
    await assertFails(unauthDb.collection("properties").doc("property1").get());
    await assertFails(unauthDb.collection("bookings").doc("anyId").get());
  });
});

describe("Firestore Security Rules - User Profiles (Collection: 'users')", () => {
  // --- Create ---
  it("should allow an authenticated user to create their own user profile", async () => {
    const newUserProfile = {
      name: "Charlie Tester",
      email: "charlie@example.com",
      phone: "555-123-4567",
      profilePicture: "https://example.com/charlie.jpg",
      isAdmin: false, // Must be false for non-admin
      createdAt: Timestamp.now(),
    };
    await assertSucceeds(testEnv.authenticatedContext("charlieId").firestore().collection("users").doc("charlieId").set(newUserProfile));
  });

  it("should deny an authenticated user from creating another user's profile", async () => {
    const newUserProfile = { /* Minimal valid data to allow rule evaluation */
      name: "Charlie Tester", email: "charlie@example.com", phone: "555-123-4567",
      profilePicture: "https://example.com/charlie.jpg", isAdmin: false, createdAt: Timestamp.now(),
    };
    await assertFails(aliceDb.collection("users").doc("charlieId").set(newUserProfile)); // Alice creating for Charlie
  });

  it("should deny user create if 'isAdmin' is true for non-admin user", async () => {
    const newUserProfile = {
      name: "Evil Hacker",
      email: "evil@example.com",
      phone: "999-999-9999",
      profilePicture: "https://example.com/evil.jpg",
      isAdmin: true, // Attempting to create as admin
      createdAt: Timestamp.now(),
    };
    await assertFails(testEnv.authenticatedContext("evilId").firestore().collection("users").doc("evilId").set(newUserProfile));
  });

  // --- Read ---
  it("should allow an authenticated user to read their own user profile", async () => {
    await assertSucceeds(aliceDb.collection("users").doc("aliceId").get());
  });

  it("should deny an authenticated user from reading another user's profile", async () => {
    await assertFails(aliceDb.collection("users").doc("bobId").get());
  });

  it("should allow an admin to read any user profile", async () => {
    await assertSucceeds(adminDb.collection("users").doc("aliceId").get());
    await assertSucceeds(adminDb.collection("users").doc("bobId").get());
  });

  // --- Update ---
  it("should allow an authenticated user to update their own user profile (partial update)", async () => {
    const updatedProfile = {
      name: "Alice Wonderwoman",
      email: "alice_updated@example.com",
    };
    await assertSucceeds(aliceDb.collection("users").doc("aliceId").update(updatedProfile));
  });

  it("should allow an admin to update any user profile", async () => {
    const adminUpdatedUser = {
      name: "Bob The Builder Admin",
      email: "bob_admin_updated@example.com",
      phone: "999-999-9999",
    };
    await assertSucceeds(adminDb.collection("users").doc("bobId").update(adminUpdatedUser));
  });

  it("should deny an authenticated user from updating another user's profile", async () => {
    const updatedProfile = { name: "Bob Changed", email: "bob_updated@example.com" };
    await assertFails(aliceDb.collection("users").doc("bobId").update(updatedProfile));
  });

  // ** Test: Prevent isAdmin self-elevation **
  it("should deny a non-admin user from setting their own isAdmin to true on update (partial)", async () => {
    // Attempt to update Alice's profile and change isAdmin to true
    await assertFails(aliceDb.collection("users").doc("aliceId").update({ isAdmin: true }));
  });

  it("should deny a non-admin user from setting their own isAdmin to true on update (full replacement)", async () => {
    // Test full replacement too, ensuring all required fields are present
    await assertFails(aliceDb.collection("users").doc("aliceId").set({
      name: "Alice Wonderland", email: "alice@example.com", phone: "123-456-7890",
      profilePicture: "https://example.com/alice.jpg",
      isAdmin: true, // Attempting to self-elevate
      createdAt: Timestamp.now(),
    }));
  });

  // --- Delete ---
  it("should deny non-admin users from deleting their own user profile", async () => {
    await assertFails(aliceDb.collection("users").doc("aliceId").delete());
  });

  it("should allow admin to delete any user profile", async () => {
    // Need to create a user first to delete
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("users").doc("deleteMe").set({
        name: "Delete Me", email: "delete@me.com", phone: "111", profilePicture: "test", isAdmin: false, createdAt: Timestamp.now()
      });
    });
    await assertSucceeds(adminDb.collection("users").doc("deleteMe").delete());
  });

  // --- Field-level Validation for Users ---
  it("should deny user create if 'name' is missing", async () => {
    const invalidProfile = { email: "invalid@example.com", phone: "123", profilePicture: "img", isAdmin: false, createdAt: Timestamp.now() };
    await assertFails(testEnv.authenticatedContext("inv1").firestore().collection("users").doc("inv1").set(invalidProfile));
  });

  it("should deny user create if 'email' is invalid", async () => {
    const invalidProfile = { name: "Invalid", email: "invalid-email", phone: "123", profilePicture: "img", isAdmin: false, createdAt: Timestamp.now() };
    await assertFails(testEnv.authenticatedContext("inv2").firestore().collection("users").doc("inv2").set(invalidProfile));
  });

  it("should deny user create if 'createdAt' is missing", async () => {
    const invalidProfile = { name: "NoDateUser", email: "nodate@example.com", phone: "123", profilePicture: "img", isAdmin: false };
    await assertFails(testEnv.authenticatedContext("inv3").firestore().collection("users").doc("inv3").set(invalidProfile));
  });

  it("should deny user create if extra, unauthorized fields are present", async () => {
    const invalidProfile = { name: "ExtraField", email: "extra@example.com", phone: "123", profilePicture: "img", isAdmin: false, createdAt: Timestamp.now(), unauthorizedField: "hacker" };
    await assertFails(testEnv.authenticatedContext("inv4").firestore().collection("users").doc("inv4").set(invalidProfile));
  });

  it("should deny user update if extra, unauthorized fields are present", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("users").doc("userToUpdateExtraField").set({ name: "User", email: "update@example.com", phone: "111", profilePicture: "img", isAdmin: false, createdAt: Timestamp.now() });
    });
    const updatedProfile = { name: "User Updated", unauthorizedField: "hacker" };
    await assertFails(aliceDb.collection("users").doc("userToUpdateExtraField").update(updatedProfile));
  });
});

describe("Firestore Security Rules - Properties & Cottages Collections", () => {
  // --- Properties ---
  it("should allow any authenticated user to read properties", async () => {
    await assertSucceeds(aliceDb.collection("properties").doc("property1").get());
    await assertSucceeds(bobDb.collection("properties").doc("property1").get());
  });

  it("should allow admin to create, update, and delete properties", async () => {
    const newProperty = { name: "Cozy Cabin", location: "Forest", ownerId: "adminId", createdAt: Timestamp.now() };
    await assertSucceeds(adminDb.collection("properties").doc("property2").set(newProperty));
    await assertSucceeds(adminDb.collection("properties").doc("property2").update({ name: "Super Cozy Cabin" }));
    await assertSucceeds(adminDb.collection("properties").doc("property2").delete());
  });

  it("should deny non-admin users from creating, updating, or deleting properties", async () => {
    const newProperty = { name: "My Place", location: "City", ownerId: "aliceId", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("properties").doc("property3").set(newProperty));
    await assertFails(aliceDb.collection("properties").doc("property1").update({ name: "Alice's Villa" }));
    await assertFails(aliceDb.collection("properties").doc("property1").delete());
  });

  // --- Cottages Sub-collection ---
  it("should allow any authenticated user to read cottages", async () => {
    await assertSucceeds(aliceDb.collection("properties").doc("property1").collection("cottages").doc("cottageA").get());
  });

  it("should allow admin to create, update, and delete cottages", async () => {
    const newCottage = { name: "Forest Nook", beds: 1, pricePerNight: 100, createdAt: Timestamp.now() };
    await assertSucceeds(adminDb.collection("properties").doc("property1").collection("cottages").doc("cottageB").set(newCottage));
    await assertSucceeds(adminDb.collection("properties").doc("property1").collection("cottages").doc("cottageB").update({ pricePerNight: 120 }));
    await assertSucceeds(adminDb.collection("properties").doc("property1").collection("cottages").doc("cottageB").delete());
  });

  it("should deny non-admin users from creating, updating, or deleting cottages", async () => {
    const newCottage = { name: "My Cozy Place", beds: 3, pricePerNight: 150, createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("properties").doc("property1").collection("cottages").doc("cottageC").set(newCottage));
    await assertFails(aliceDb.collection("properties").doc("property1").collection("cottages").doc("cottageA").update({ pricePerNight: 180 }));
    await assertFails(aliceDb.collection("properties").doc("property1").collection("cottages").doc("cottageA").delete());
  });
});

describe("Firestore Security Rules - Bookings Collection", () => {
  // --- Create ---
  it("should allow a user to create their own booking for an existing property with status 'pending'", async () => {
    const bookingData = {
      userId: "aliceId",
      propertyId: "property1",
      cottageId: "cottageA",
      checkInDate: Timestamp.now(),
      checkOutDate: Timestamp.fromMillis(Timestamp.now().toMillis() + 86400000), // 1 day later
      numGuests: 2,
      totalPrice: 400,
      status: "pending", // Must be pending
      createdAt: Timestamp.now(),
    };
    await assertSucceeds(aliceDb.collection("bookings").doc("bookingAlice1").set(bookingData));
  });

  it("should deny a user from creating a booking for another user", async () => {
    const bookingData = { userId: "bobId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 1, totalPrice: 200, status: "pending", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("bookings").doc("bookingAliceToBob").set(bookingData));
  });

  it("should deny a user from creating a booking with status 'confirmed' or 'rejected'", async () => {
    const confirmedBooking = { userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 1, totalPrice: 200, status: "confirmed", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("bookings").doc("bookingAliceConfirmed").set(confirmedBooking));

    const rejectedBooking = { userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 1, totalPrice: 200, status: "rejected", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("bookings").doc("bookingAliceRejected").set(rejectedBooking));
  });

  // --- Read ---
  it("should allow a user to read their own booking", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("tempAliceBooking").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 1, totalPrice: 100, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertSucceeds(aliceDb.collection("bookings").doc("tempAliceBooking").get());
  });

  it("should deny a user from reading another user's booking", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("tempBobBooking").set({
        userId: "bobId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 1, totalPrice: 100, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertFails(aliceDb.collection("bookings").doc("tempBobBooking").get());
  });

  it("should allow an admin to read any booking", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("adminReadBooking").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 1, totalPrice: 100, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertSucceeds(adminDb.collection("bookings").doc("adminReadBooking").get());
  });

  // --- Update ---
  it("should allow a user to update their own booking's numGuests, checkInDate, checkOutDate", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("aliceUpdateFields").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA",
        // Setting checkIn/Out dates to allow a valid update scenario
        checkInDate: Timestamp.fromMillis(Timestamp.now().toMillis() + 86400000), // Original: 1 day from now
        checkOutDate: Timestamp.fromMillis(Timestamp.now().toMillis() + (86400000 * 5)), // Original: 5 days from now
        numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now(),
      });
    });
    // Update checkInDate to 3 days from now. Original checkOutDate (5 days) is still >= new checkInDate (3 days).
    const updatedBooking = {
      numGuests: 3,
      checkInDate: Timestamp.fromMillis(Timestamp.now().toMillis() + (86400000 * 3))
    };
    await assertSucceeds(aliceDb.collection("bookings").doc("aliceUpdateFields").update(updatedBooking));
  });

  it("should allow a user to update their own booking status to 'cancelled'", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("aliceCancelBooking").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertSucceeds(aliceDb.collection("bookings").doc("aliceCancelBooking").update({ status: "cancelled" }));
  });

  // ** Test: Deny unauthorized booking status change **
  it("should deny a non-admin user from updating their booking status to 'confirmed'", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("aliceToConfirm").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertFails(aliceDb.collection("bookings").doc("aliceToConfirm").update({ status: "confirmed" }));
  });

  it("should deny a non-admin user from updating their booking status to 'rejected'", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("aliceToReject").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertFails(aliceDb.collection("bookings").doc("aliceToReject").update({ status: "rejected" }));
  });

  // ** Test: Deny totalPrice manipulation **
  it("should deny a non-admin user from updating their booking totalPrice", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("alicePriceChange").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertFails(aliceDb.collection("bookings").doc("alicePriceChange").update({ totalPrice: 10 })); // Try to change to a low price
  });

  it("should deny a user from updating another user's booking", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("bobToUpdate").set({
        userId: "bobId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertFails(aliceDb.collection("bookings").doc("bobToUpdate").update({ numGuests: 3 }));
  });

  it("should allow an admin to update any booking (including status and price)", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("adminUpdateBooking").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now(),
      });
    });
    const adminUpdatedBooking = { status: "confirmed", totalPrice: 500 };
    await assertSucceeds(adminDb.collection("bookings").doc("adminUpdateBooking").update(adminUpdatedBooking));
  });

  // --- Delete ---
  it("should allow an admin to delete any booking", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("adminDeleteBooking").set({
        userId: "bobId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 1, totalPrice: 100, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertSucceeds(adminDb.collection("bookings").doc("adminDeleteBooking").delete());
  });

  it("should deny non-admin users from deleting any booking", async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().collection("bookings").doc("aliceDeleteBooking").set({
        userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 1, totalPrice: 100, status: "pending", createdAt: Timestamp.now(),
      });
    });
    await assertFails(aliceDb.collection("bookings").doc("aliceDeleteBooking").delete());
  });

  // --- Field-level Validation for Bookings ---
  it("should deny booking create if 'userId' does not match authenticated user", async () => {
    const bookingData = { userId: "bobId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("bookings").doc("invalidBooking1").set(bookingData));
  });

  it("should deny booking create if 'numGuests' is zero or negative", async () => {
    const bookingData = { userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 0, totalPrice: 400, status: "pending", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("bookings").doc("invalidBooking2").set(bookingData));
  });

  it("should deny booking create if 'totalPrice' is zero or negative", async () => {
    const bookingData = { userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: -100, status: "pending", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("bookings").doc("invalidBooking3").set(bookingData));
  });

  it("should deny booking create if 'status' is invalid", async () => {
    const bookingData = { userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: Timestamp.now(), checkOutDate: Timestamp.now(), numGuests: 2, totalPrice: 400, status: "invalidStatus", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("bookings").doc("invalidBooking4").set(bookingData));
  });

  it("should deny booking create if 'checkInDate' is after 'checkOutDate'", async () => {
    const checkIn = Timestamp.fromMillis(Timestamp.now().toMillis() + 86400000); // CheckIn is 1 day later
    const checkOut = Timestamp.now();                                        // CheckOut is now
    const bookingData = { userId: "aliceId", propertyId: "property1", cottageId: "cottageA", checkInDate: checkIn, checkOutDate: checkOut, numGuests: 2, totalPrice: 400, status: "pending", createdAt: Timestamp.now() };
    await assertFails(aliceDb.collection("bookings").doc("invalidBooking5").set(bookingData));
  });
});
