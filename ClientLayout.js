"use client";

import NavBar from "./NavBar";
import Footer from "./Footer";

export default function ClientLayout({ children }) {
  return (
    <>
      <NavBar />
      <div className="container">{children}</div>
      <Footer />
    </>
  );
}
