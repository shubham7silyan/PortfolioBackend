console.log('✅ Node.js is working');
console.log('📁 Current directory:', __dirname);
console.log('🔧 Node version:', process.version);

// Test basic require
try {
    require('dotenv').config();
    console.log('✅ dotenv loaded');
} catch (error) {
    console.error('❌ dotenv error:', error.message);
}

// Test express
try {
    const express = require('express');
    console.log('✅ express loaded');
} catch (error) {
    console.error('❌ express error:', error.message);
}

// Test mongoose
try {
    const mongoose = require('mongoose');
    console.log('✅ mongoose loaded');
} catch (error) {
    console.error('❌ mongoose error:', error.message);
}

console.log('🏁 Test completed');
