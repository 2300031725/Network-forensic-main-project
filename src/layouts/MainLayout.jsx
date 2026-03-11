import React from 'react';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';

const MainLayout = ({ children }) => {
    return (
        <div className="flex h-screen overflow-x-hidden">
            <Sidebar />
            <div className="flex flex-col flex-1 overflow-visible">
                <Header />
                <main className="flex-1 overflow-x-hidden overflow-y-auto p-8">
                    {children}
                </main>
            </div>
        </div>
    );
};

export default MainLayout;
