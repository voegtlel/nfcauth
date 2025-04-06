package de.infornautik.nfcauth

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView

class ReadersAdapter(private val onReaderClick: (ReaderInfo) -> Unit) : 
    ListAdapter<ReaderInfo, ReadersAdapter.ReaderViewHolder>(ReaderDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ReaderViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(android.R.layout.simple_list_item_1, parent, false)
        return ReaderViewHolder(view)
    }

    override fun onBindViewHolder(holder: ReaderViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class ReaderViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val textView: TextView = itemView as TextView

        fun bind(reader: ReaderInfo) {
            textView.text = reader.readerName
            itemView.setOnClickListener { onReaderClick(reader) }
        }
    }

    private class ReaderDiffCallback : DiffUtil.ItemCallback<ReaderInfo>() {
        override fun areItemsTheSame(oldItem: ReaderInfo, newItem: ReaderInfo): Boolean {
            return oldItem.readerId == newItem.readerId
        }

        override fun areContentsTheSame(oldItem: ReaderInfo, newItem: ReaderInfo): Boolean {
            return oldItem == newItem
        }
    }
} 