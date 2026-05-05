import React from "react";
import { createRoot } from "react-dom/client";
import SecureFileManager from "./secure-file-manager";

const root = createRoot(document.getElementById("root"));
root.render(<SecureFileManager />);